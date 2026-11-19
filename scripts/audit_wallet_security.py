#!/usr/bin/env python3
"""Independent internal evaluator; never imports or executes wallet runtime.

Review-derived AST contracts + crash-state exploration + direct byte identity.
Not external human review, full formal verification or a second build witness.
"""
import argparse,ast,hashlib,json,subprocess
from pathlib import Path

PINS={'wamd':'fe04a61f17eb8047f1d2a537ebcb61b45cbde14c491bc332d2a2ab7ee18237ba',
      'wam-cli':'2b19fdac692cbed5810b6fa9663ac89f25ab8f346da84c5fd13bf2b8535e3e19'}
WSP='ac55f13423620252bdbf848c7e8a280c3b84721e'

def sha(path): return hashlib.sha256(path.read_bytes()).hexdigest()
def name(node):
    if isinstance(node,ast.Name): return node.id
    if isinstance(node,ast.Attribute): return name(node.value)+'.'+node.attr
    if isinstance(node,ast.Call): return name(node.func)
    return ''

_OSERROR_CATCHERS=frozenset({
    'OSError','IOError','EnvironmentError','Exception','BaseException',
    'builtins.OSError','builtins.IOError','builtins.EnvironmentError',
    'builtins.Exception','builtins.BaseException',
})
_TRY_NODES=(ast.Try,getattr(ast,'TryStar',ast.Try))

_FULLFLUSH_PRIMITIVES=frozenset({'full_flush','flush_directory'})
_MATCH_NODES=tuple(c for c in (getattr(ast,'MatchAs',None),getattr(ast,'MatchStar',None),
                                getattr(ast,'MatchMapping',None)) if c is not None)

def _target_names(target):
    if isinstance(target,ast.Name): yield target.id
    elif isinstance(target,(ast.Tuple,ast.List)):
        for elt in target.elts: yield from _target_names(elt)
    elif isinstance(target,ast.Starred): yield from _target_names(target.value)

def _iter_target_nodes(target):
    yield target
    if isinstance(target,(ast.Tuple,ast.List)):
        for elt in target.elts: yield from _iter_target_nodes(elt)
    elif isinstance(target,ast.Starred): yield from _iter_target_nodes(target.value)

def _iter_write_targets(node):
    if isinstance(node,(ast.Assign,ast.Delete)):
        for t in node.targets: yield from _iter_target_nodes(t)
    elif isinstance(node,(ast.AnnAssign,ast.AugAssign,ast.For,ast.AsyncFor,ast.NamedExpr)):
        yield from _iter_target_nodes(node.target)
    elif isinstance(node,(ast.With,ast.AsyncWith)):
        for item in node.items:
            if item.optional_vars is not None: yield from _iter_target_nodes(item.optional_vars)

def _bound_targets_in_node(node,*,skip_aliases=(),allow_stdlib=()):
    if isinstance(node,ast.FunctionDef): yield ('func',node.name)
    elif isinstance(node,(ast.AsyncFunctionDef,ast.ClassDef)): yield ('other_def',node.name)
    elif isinstance(node,(ast.Assign,ast.AnnAssign,ast.AugAssign,ast.For,ast.AsyncFor,
                          ast.With,ast.AsyncWith,ast.NamedExpr)):
        for t in _iter_write_targets(node):
            if isinstance(t,ast.Name): yield ('bind',t.id)
    elif isinstance(node,ast.Delete):
        for t in _iter_write_targets(node):
            if isinstance(t,ast.Name): yield ('del',t.id)
    elif isinstance(node,ast.ExceptHandler) and isinstance(node.name,str): yield ('bind',node.name)
    elif _MATCH_NODES and isinstance(node,_MATCH_NODES):
        attr='rest' if isinstance(node,ast.MatchMapping) else 'name'
        val=getattr(node,attr,None)
        if isinstance(val,str): yield ('bind',val)
    elif isinstance(node,ast.Import):
        for alias in node.names:
            if alias in skip_aliases: continue
            if alias.name in allow_stdlib and alias.asname is None: continue
            yield ('bind',(alias.asname or alias.name).split('.')[0])
    elif isinstance(node,ast.ImportFrom):
        for alias in node.names:
            if alias in skip_aliases: continue
            if alias.name=='*': yield ('star','*')
            else: yield ('bind',(alias.asname or alias.name).split('.')[0])

def _assigned_names(tree,*,skip_aliases=(),allow_stdlib=()):
    bound=set()
    for node in ast.walk(tree):
        for kind,ident in _bound_targets_in_node(node,skip_aliases=skip_aliases,allow_stdlib=allow_stdlib):
            if kind!='star': bound.add(ident)
    return bound

def _walk_module_scope(node):
    yield node
    if isinstance(node,(ast.FunctionDef,ast.AsyncFunctionDef)):
        for sub in (*node.decorator_list,*node.args.defaults,
                    *(d for d in node.args.kw_defaults if d is not None)):
            yield from _walk_module_scope(sub)
        return
    if isinstance(node,ast.ClassDef):
        for sub in (*node.decorator_list,*node.bases,*node.keywords):
            yield from _walk_module_scope(sub)
        return
    if isinstance(node,ast.Lambda):
        for sub in (*node.args.defaults,*(d for d in node.args.kw_defaults if d is not None)):
            yield from _walk_module_scope(sub)
        return
    for child in ast.iter_child_nodes(node): yield from _walk_module_scope(child)

def _count_module_bindings(tree,targets):
    counts={}
    invalid=False
    for node in _walk_module_scope(tree):
        for kind,ident in _bound_targets_in_node(node):
            if kind=='star': invalid=True
            elif ident in targets:
                if kind=='other_def': invalid=True
                counts[ident]=counts.get(ident,0)+1
    return counts,invalid

def _resolve_expr(node,env,seen=()):
    while isinstance(node,ast.Name) and node.id in env and node.id not in seen:
        seen=seen+(node.id,)
        node=env[node.id]
    return node

def _is_globals_call(node,env=()):
    node=_resolve_expr(node,env) if env else node
    return (isinstance(node,ast.Call) and name(node.func) in ('globals','builtins.globals')
            and not node.args and not node.keywords)

def _is_dict_expr(node,env=()):
    node=_resolve_expr(node,env) if env else node
    return ((isinstance(node,ast.Name) and node.id=='__dict__')
            or (isinstance(node,ast.Attribute) and node.attr=='__dict__')
            or (isinstance(node,ast.Call) and name(node.func) in ('vars','builtins.vars')))

def _mentions_target(node,targets,env=()):
    for n in ast.walk(node):
        if isinstance(n,ast.Constant) and isinstance(n.value,str) and n.value in targets: return True
        if env and isinstance(n,ast.Name):
            resolved=_resolve_expr(n,env)
            if isinstance(resolved,ast.Constant) and isinstance(resolved.value,str) and resolved.value in targets:
                return True
    return False

def _has_dynamic_rebind(tree,targets,module_targets=()):
    env=_single_bindings(tree.body,tree)
    for node in ast.walk(tree):
        if isinstance(node,ast.Global) and any(n in targets for n in node.names): return True
        if isinstance(node,ast.Call):
            fn=name(node.func)
            if fn in ('setattr','builtins.setattr','delattr','builtins.delattr'):
                if _mentions_target(node,targets,env): return True
                if (module_targets and _mentions_target(node,_FULLFLUSH_PRIMITIVES,env)
                        and any(isinstance(a,ast.Name) and a.id in module_targets for a in node.args)):
                    return True
            elif isinstance(node.func,ast.Attribute):
                val,attr=node.func.value,node.func.attr
                if (_is_globals_call(val,env) or _is_dict_expr(val,env)) and attr in ('update','setdefault','__setitem__','pop'):
                    if any(kw.arg in targets for kw in node.keywords) or _mentions_target(node,targets,env):
                        return True
                if (module_targets and isinstance(val,ast.Attribute) and val.attr=='__dict__'
                        and name(val.value) in module_targets and attr in ('update','setdefault','__setitem__','pop')
                        and (any(kw.arg in _FULLFLUSH_PRIMITIVES for kw in node.keywords)
                             or _mentions_target(node,_FULLFLUSH_PRIMITIVES,env))):
                    return True
                if attr in ('__setattr__','__delattr__'):
                    if _mentions_target(node,targets,env): return True
                    if module_targets and name(val) in module_targets and _mentions_target(node,_FULLFLUSH_PRIMITIVES,env):
                        return True
        for t in _iter_write_targets(node):
            if isinstance(t,ast.Subscript):
                if (_is_globals_call(t.value,env) or _is_dict_expr(t.value,env)) and _mentions_target(t.slice,targets,env):
                    return True
                if (module_targets and isinstance(t.value,ast.Attribute) and t.value.attr=='__dict__'
                        and name(t.value.value) in module_targets and _mentions_target(t.slice,_FULLFLUSH_PRIMITIVES,env)):
                    return True
            elif isinstance(t,ast.Attribute):
                if t.attr in targets: return True
                if module_targets and (name(t) in module_targets
                        or (name(t.value) in module_targets and t.attr in _FULLFLUSH_PRIMITIVES)):
                    return True
    return False

def _resolve_fullflush_calls(storage):
    """Return local call names proven to resolve to fullflush.full_flush."""
    direct,modules,skip_aliases=set(),set(),[]
    imported_locals,pkg_imports,module_refs=set(),set(),set()
    for node in ast.walk(storage):
        if isinstance(node,ast.ImportFrom):
            if (node.level==1 and node.module=='fullflush') or (node.level==0 and node.module=='wam_regtest.fullflush'):
                for alias in node.names:
                    if alias.name=='*': return None
                    local=alias.asname or alias.name
                    if local in imported_locals: return None
                    imported_locals.add(local)
                    skip_aliases.append(alias)
                    if alias.name=='full_flush': direct.add(local)
            elif (node.level==1 and node.module is None) or (node.level==0 and node.module=='wam_regtest'):
                for alias in node.names:
                    if alias.name=='fullflush':
                        local=alias.asname or 'fullflush'
                        if local in imported_locals: return None
                        imported_locals.add(local)
                        skip_aliases.append(alias)
                        modules.add(local)
                        module_refs.add(local)
        elif isinstance(node,ast.Import):
            for alias in node.names:
                if alias.name=='wam_regtest.fullflush':
                    skip_aliases.append(alias)
                    if alias.asname:
                        if alias.asname in imported_locals: return None
                        imported_locals.add(alias.asname)
                        modules.add(alias.asname)
                        module_refs.add(alias.asname)
                    else:
                        pkg_imports.add('wam_regtest')
                        modules.add('wam_regtest.fullflush')
                        module_refs.add('wam_regtest.fullflush')
                elif alias.asname is None and (alias.name=='wam_regtest' or alias.name.startswith('wam_regtest.')):
                    skip_aliases.append(alias)
    skip_tuple=tuple(skip_aliases)
    if imported_locals or pkg_imports:
        for node in ast.walk(storage):
            if isinstance(node,ast.ImportFrom) and any(a not in skip_tuple and a.name=='*' for a in node.names):
                return None
    shadowed=_assigned_names(storage,skip_aliases=skip_tuple,allow_stdlib=('os',))
    if 'os' in shadowed: return None
    watched=imported_locals|pkg_imports
    if watched&shadowed: return None
    if watched and _has_dynamic_rebind(storage,watched,module_targets=module_refs): return None
    calls=set(direct)
    calls.update(f'{m}.full_flush' for m in modules)
    return calls

def _is_darwin_platform_check(test):
    if not (isinstance(test,ast.Compare) and len(test.ops)==1 and isinstance(test.ops[0],ast.Eq)
            and len(test.comparators)==1):
        return False
    left,right=test.left,test.comparators[0]
    return ((name(left)=='sys.platform' and isinstance(right,ast.Constant) and right.value=='darwin')
            or (isinstance(left,ast.Constant) and left.value=='darwin' and name(right)=='sys.platform'))

def _single_bindings(stmts,full_scope):
    counts={}
    for node in ast.walk(full_scope):
        if isinstance(node,ast.Assign):
            for t in node.targets:
                for k in _target_names(t): counts[k]=counts.get(k,0)+1
        elif isinstance(node,ast.AnnAssign):
            for k in _target_names(node.target): counts[k]=counts.get(k,0)+1
        elif isinstance(node,ast.AugAssign):
            for k in _target_names(node.target): counts[k]=counts.get(k,0)+1
    env={}
    for stmt in stmts:
        if isinstance(stmt,ast.Assign) and len(stmt.targets)==1 and isinstance(stmt.targets[0],ast.Name):
            k=stmt.targets[0].id
            if counts.get(k)==1: env[k]=stmt.value
        elif isinstance(stmt,ast.AnnAssign) and isinstance(stmt.target,ast.Name) and stmt.value is not None:
            k=stmt.target.id
            if counts.get(k)==1: env[k]=stmt.value
    return env

def _is_51_expr(node,env,seen=()):
    if isinstance(node,ast.Constant): return type(node.value) is int and node.value==51
    if isinstance(node,ast.Name) and node.id in env and node.id not in seen:
        return _is_51_expr(env[node.id],env,seen+(node.id,))
    return False

def _is_fullfsync_expr(node,env,imported_attr=False,seen=()):
    if node is None: return False
    if isinstance(node,ast.Constant): return type(node.value) is int and node.value==51
    if isinstance(node,ast.Attribute): return name(node)=='fcntl.F_FULLFSYNC'
    if isinstance(node,ast.Name):
        if imported_attr and node.id=='F_FULLFSYNC': return True
        if node.id in env and node.id not in seen:
            return _is_fullfsync_expr(env[node.id],env,imported_attr,seen+(node.id,))
        return False
    if isinstance(node,ast.Call) and name(node.func)=='getattr' and not node.keywords:
        if len(node.args) in (2,3) and name(node.args[0])=='fcntl':
            arg1=node.args[1]
            if isinstance(arg1,ast.Constant) and arg1.value=='F_FULLFSYNC':
                return len(node.args)==2 or _is_51_expr(node.args[2],env)
    return False

def _is_fcntl_fullfsync_call(call,env,imported_attr=False):
    if not (isinstance(call,ast.Call) and name(call.func)=='fcntl.fcntl'): return False
    cmd=call.args[1] if len(call.args)>=2 else next(
        (kw.value for kw in call.keywords if kw.arg in ('cmd','op')),None)
    return _is_fullfsync_expr(cmd,env,imported_attr=imported_attr)

def _catches_oserror_type(expr):
    if expr is None: return True
    if name(expr) in _OSERROR_CATCHERS: return True
    if isinstance(expr,ast.Tuple): return any(_catches_oserror_type(elt) for elt in expr.elts)
    return False

def _handler_always_reraises(stmts):
    if not stmts: return False
    last=stmts[-1]
    if isinstance(last,ast.Raise) and last.exc is None: return True
    if isinstance(last,ast.If) and last.orelse:
        return _handler_always_reraises(last.body) and _handler_always_reraises(last.orelse)
    return False

def _always_returns(stmts):
    if not stmts: return False
    last=stmts[-1]
    if isinstance(last,ast.Return): return True
    if isinstance(last,ast.If) and last.orelse:
        return _always_returns(last.body) and _always_returns(last.orelse)
    if isinstance(last,_TRY_NODES) and not last.handlers:
        return _always_returns(last.body) or _always_returns(last.finalbody)
    return False

def _iter_exec_calls(node):
    if isinstance(node,(ast.FunctionDef,ast.AsyncFunctionDef,ast.ClassDef,ast.Lambda)): return
    if isinstance(node,ast.Call): yield node
    for child in ast.iter_child_nodes(node): yield from _iter_exec_calls(child)

def _has_call(nodes,target,*,exec_only=True):
    if exec_only:
        return any(name(c.func)==target for stmt in nodes for c in _iter_exec_calls(stmt))
    mod=ast.Module(body=list(nodes),type_ignores=[])
    return any(isinstance(n,ast.Call) and name(n.func)==target for n in ast.walk(mod))

def _find_darwin_if(stmts,enclosing_tries=()):
    for idx,stmt in enumerate(stmts):
        if isinstance(stmt,ast.If) and _is_darwin_platform_check(stmt.test):
            return stmts,idx,stmt,enclosing_tries
        if isinstance(stmt,_TRY_NODES):
            found=_find_darwin_if(stmt.body,enclosing_tries+(stmt,))
            if found is not None: return found
    return None

def _has_fcntl_before_return(stmts,env,imported_attr):
    for stmt in stmts:
        calls=[n for n in _iter_exec_calls(stmt) if _is_fcntl_fullfsync_call(n,env,imported_attr)]
        if isinstance(stmt,_TRY_NODES):
            if _has_fcntl_before_return(stmt.body,env,imported_attr): return True
        elif calls and not isinstance(stmt,(ast.If,ast.For,ast.AsyncFor,ast.While)):
            return True
        if isinstance(stmt,(ast.Return,ast.Raise)): return False
    return False

def _verify_fullflush(root):
    """Independently verify fullflush.py darwin F_FULLFSYNC and non-darwin os.fsync."""
    path=root/'src/wam_regtest/fullflush.py'
    if not path.is_file(): return False
    try: tree=ast.parse(path.read_text())
    except (OSError,SyntaxError): return False
    if {'os','sys','fcntl'}&_assigned_names(tree,allow_stdlib=('os','sys','fcntl')): return False
    counts,invalid=_count_module_bindings(tree,_FULLFLUSH_PRIMITIVES)
    if invalid or any(counts.get(n)!=1 for n in _FULLFLUSH_PRIMITIVES): return False
    if _has_dynamic_rebind(tree,_FULLFLUSH_PRIMITIVES): return False
    funcs={n.name:n for n in tree.body if isinstance(n,ast.FunctionDef)}
    full_flush_fn,flush_dir_fn=funcs.get('full_flush'),funcs.get('flush_directory')
    if full_flush_fn is None or flush_dir_fn is None: return False
    if not _has_call(flush_dir_fn.body,'os.fsync'): return False
    located=_find_darwin_if(full_flush_fn.body)
    if located is None: return False
    container_stmts,idx,darwin_if,enclosing_tries=located
    if _has_call(container_stmts[:idx],'os.fsync',exec_only=False): return False
    if _has_call(darwin_if.body,'os.fsync',exec_only=False): return False
    inner_tries=[n for n in ast.walk(ast.Module(body=darwin_if.body,type_ignores=[]))
                 if isinstance(n,_TRY_NODES)]
    for try_node in (*enclosing_tries,*inner_tries):
        if any(_catches_oserror_type(h.type) and not _handler_always_reraises(h.body)
               for h in try_node.handlers):
            return False
    if not _always_returns(darwin_if.body): return False
    module_env=_single_bindings(tree.body,tree)
    branch_env=_single_bindings(darwin_if.body,full_flush_fn)
    env={**module_env,**branch_env}
    imported_attr=any(isinstance(n,ast.ImportFrom) and n.module=='fcntl'
                      and any(a.name=='F_FULLFSYNC' and a.asname is None for a in n.names)
                      for n in (*tree.body,*ast.walk(full_flush_fn)))
    if not _has_fcntl_before_return(darwin_if.body,env,imported_attr): return False
    return _has_call(darwin_if.orelse,'os.fsync') or _has_call(container_stmts[idx+1:],'os.fsync')

def storage_contract(root):
    """Verify encrypted_storage publication custody and flush durability contract."""
    root=Path(root)
    path=root/'src/wam_regtest/encrypted_storage.py'
    if not path.is_file(): return False
    try: storage=ast.parse(path.read_text())
    except (OSError,SyntaxError): return False
    primitive_calls=_resolve_fullflush_calls(storage)
    if primitive_calls is None: return False
    storage_calls={name(n.func) for n in ast.walk(storage) if isinstance(n,ast.Call)}
    if not {'os.link','os.fchmod'}<=storage_calls: return False
    uses_fsync='os.fsync' in storage_calls
    uses_primitive=bool(primitive_calls&storage_calls)
    if not (uses_fsync or uses_primitive): return False
    if uses_primitive and not _verify_fullflush(root): return False
    return True
def method(tree,label):
    cls=next(n for n in tree.body if isinstance(n,ast.ClassDef) and n.name=='WalletSession')
    return next(n for n in cls.body if isinstance(n,ast.FunctionDef) and n.name==label)
def events(fn):
    return [(n.lineno,name(n.func),n) for n in ast.walk(fn) if isinstance(n,ast.Call)]
def line(calls,label): return min(n for n,k,_ in calls if k==label)
def uncertain_before_submission(broadcast_fn):
    """The uncertain write is still before the first save, which is before submission.

    The SQL may sit inline, or in mark_reservations_uncertain_before_submission,
    which broadcast must call before that save. The helper executes the update
    and does not submit.
    """
    save_at=line(events(broadcast_fn),'self._save')
    inline=any(isinstance(n,ast.Constant) and isinstance(n.value,str)
        and "state='uncertain'" in n.value and n.lineno<save_at for n in ast.walk(broadcast_fn))
    if inline: return True
    marker='mark_reservations_uncertain_before_submission'
    if not any(k==marker and n<save_at for n,k,_ in events(broadcast_fn)): return False
    helper=ast.parse((Path(__file__).resolve().parents[1]
        /'src/wam_regtest/domain/payment_state.py').read_text())
    fn=next(n for n in helper.body if isinstance(n,ast.FunctionDef) and n.name==marker)
    sql=any(isinstance(n,ast.Constant) and isinstance(n.value,str) and "state='uncertain'" in n.value
        for n in ast.walk(fn))
    execute=any(isinstance(n,ast.Call) and name(n.func).endswith('execute') for n in ast.walk(fn))
    submits=any(isinstance(n,ast.Constant) and n.value=='sendrawtransaction' for n in ast.walk(fn))
    return bool(sql and execute and not submits)
def contracts(tree):
    s,b=method(tree,'sign'),method(tree,'broadcast'); se,be=events(s),events(b)
    lease=all(any(isinstance(n,ast.With) and any(name(i.context_expr)=='self.vault.anchor.lease'
              for i in n.items) for n in ast.walk(f)) for f in (s,b))
    return {'sign_broadcast_lease':lease,
       'exact_sign_review_before_crypto':any(isinstance(n,ast.Compare) and n.lineno<line(se,'Signer.sign')
           and any(name(x)=='self._review.commitment' for x in (n.left,*n.comparators)) for n in ast.walk(s)),
       'exact_broadcast_review_before_submission':any(isinstance(n,ast.Compare) and n.lineno<line(be,'Wallet.broadcast')
           and any(name(x)=='self._review.commitment' for x in (n.left,*n.comparators)) for n in ast.walk(b)),
       'live_inputs_before_sensitive_operations':line(se,'self._unchanged_inputs')<line(se,'Signer.sign') and line(be,'self._unchanged_inputs')<line(be,'Wallet.broadcast'),
       'sign_anchor_precedes_crypto':line(se,'Wallet.mark_signed')<line(se,'self._save')<line(se,'Signer.sign'),
       'broadcast_anchor_precedes_submission':line(be,'self._save')<line(be,'Wallet.broadcast'),
       'uncertain_before_submission':uncertain_before_submission(b),
       'faults_on_crypto_or_submission_failure':all(any(isinstance(n,ast.Assign)
           and any(name(t)=='self.faulted' for t in n.targets)
           and isinstance(n.value,ast.Constant) and n.value.value is True for n in ast.walk(f)) for f in (s,b))}

def state_check(*,early_signature=False,early_network=False,forget_unknown=False,replay=False):
    # Inspect every crash boundary independently of application code/evidence.
    events=['approve_sign','persist_signed','crypto','approve_broadcast','persist_uncertain','submit','unknown']
    if early_signature: events[1],events[2]=events[2],events[1]
    if early_network: events[4],events[5]=events[5],events[4]
    violations=[]
    for stop in range(len(events)+1):
        durable='draft'; signed=sent=False; sign_consent=broadcast_consent=False
        for event in events[:stop]:
            if event=='approve_sign': sign_consent=True
            elif event=='persist_signed': durable='signed'
            elif event=='crypto':
                if durable!='signed' or not sign_consent: violations.append('signature_without_anchor_or_consent')
                signed=True;sign_consent=False
            elif event=='approve_broadcast': broadcast_consent=True
            elif event=='persist_uncertain': durable='uncertain'
            elif event=='submit':
                if durable!='uncertain' or not signed or not broadcast_consent: violations.append('submission_without_uncertainty_or_consent')
                sent=True;broadcast_consent=False
            elif event=='unknown' and forget_unknown: durable='draft'
        # Crash clears volatile approvals/signatures; durable identities stay.
        if sent and durable!='uncertain': violations.append('submitted_identity_forgotten')
        if replay and signed: violations.append('approval_replayed_after_crash')
    return sorted(set(violations))

def evaluate(root,core,app=None):
    tree=ast.parse((root/'src/wam_regtest/wallet_session.py').read_text())
    results=contracts(tree)
    results['crash_model_invariants']=not state_check()
    mutants={'signature_before_anchor':{'early_signature':True},'submission_before_anchor':{'early_network':True},
             'forget_uncertain':{'forget_unknown':True},'replay_consent':{'replay':True}}
    results['model_mutation_sensitivity']=all(state_check(**args) for args in mutants.values())
    # Mutate actual source ordering: the independent contract must reject it.
    mutated=ast.parse((root/'src/wam_regtest/wallet_session.py').read_text())
    f=method(mutated,'sign')
    for node in ast.walk(f):
        if isinstance(node,ast.Call) and name(node.func)=='Signer.sign': node.lineno=0
    results['source_mutation_sensitivity']=contracts(mutated)['sign_anchor_precedes_crypto'] is False
    lock_calls=events(method(tree,'lock'))
    results['lock_closes_keys_and_plaintext_runtime']=all(any(k==label for _,k,_ in lock_calls)
        for label in ('self.ring.close','self.scanner.close','self.runtime.unlink'))
    vault=ast.parse((root/'src/wam_regtest/vault.py').read_text())
    results['stale_writer_anchor_comparison']=any(isinstance(n,ast.Compare) and name(n.left)=='previous'
        and any(name(x)=='self._expected' for x in n.comparators) for n in ast.walk(vault))
    results['backup_create_only_publication_and_fsync']=storage_contract(root)
    results['both_core_hashes_independently_pinned']=all(sha(core/n)==h for n,h in PINS.items())
    if app is not None:
        import plistlib
        info=plistlib.loads((app/'Contents/Info.plist').read_bytes())
        results['original_brand_identity']=sha(app/'Contents/Resources'/info['CFBundleIconFile'])=='833c0c6149a87d0cfa76dc4f5ee4bc03e0267aa3e326b6223e9ee7eed8b67525'
        for n,h in PINS.items():
            members=[p for p in app.rglob(n) if p.is_file() and not p.is_symlink()]
            results['bundled_'+n+'_identity']=len(members)==1 and sha(members[0])==h
        wsp=root/'wsp-upstream'
        assert subprocess.check_output(['git','-C',str(wsp),'rev-parse','HEAD'],text=True).strip()==WSP
        assert not subprocess.check_output(['git','-C',str(wsp),'status','--porcelain','--untracked-files=no','--','src/wam_sp'],text=True).strip()
        source=app/'Contents/Resources/wsp-source/src/wam_sp'
        original=wsp/'src/wam_sp'
        expected={p.relative_to(original).as_posix():sha(p) for p in original.rglob('*.py')}
        actual={p.relative_to(source).as_posix():sha(p) for p in source.rglob('*.py')}
        results['bundled_scanner_independent_source_comparison']=expected==actual
    if not all(results.values()): raise ValueError('INDEPENDENT_WALLET_CONTRACT_DENIED')
    return {'schema':'wam-regtest-independent-contracts/v1','status':'INDEPENDENT_WALLET_CONTRACTS_PASS',
        'contracts':results,'core_sha256':PINS,'wsp_source_commit':WSP,'model_crash_boundaries':8,
        'mutation_classes_detected':list(mutants),'runtime_pass_flags_trusted':False,
        'external_reviewer_approval':False,'second_builder_witness':False,'formal_verification_complete':False,
        'production_qualified':False}

def main():
    p=argparse.ArgumentParser();p.add_argument('--root',type=Path,required=True);p.add_argument('--core',type=Path,required=True)
    p.add_argument('--app',type=Path);p.add_argument('--output',type=Path,required=True);a=p.parse_args()
    result=evaluate(a.root.resolve(),a.core.resolve(),a.app.resolve() if a.app else None)
    a.output.write_text(json.dumps(result,indent=2,sort_keys=True)+'\n')
    print(result['status'])
if __name__=='__main__':
    try: main()
    except Exception: raise SystemExit('INDEPENDENT_WALLET_SECURITY_DENIED') from None
