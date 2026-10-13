/* وصلة الخادم: تستبدل التخزين المحلي (IndexedDB) وتسجيل الدخول المحلي بمصادقة وقاعدة بيانات الخادم.
   تُحمَّل بعد كود النظام الأساسي، فتعيد تعريف دوال التخزين وتسجيل الدخول ثم تشغّل النظام. */
(function(){
  'use strict';
  let me = null;
  const revs = {};
  const H = {'X-Requested-With':'inventory'};

  async function api(method, url, body, extra){
    const opt = {method, credentials:'same-origin', headers:Object.assign({}, H, extra||{})};
    if(body !== undefined){ opt.body = typeof body === 'string' ? body : JSON.stringify(body); opt.headers['Content-Type'] = 'application/json'; }
    const r = await fetch(url, opt);
    return r;
  }
  async function jsonOrErr(r){
    let d = {}; try{ d = await r.json(); }catch(e){}
    if(!r.ok){ const e = new Error(d.error || ('HTTP '+r.status)); e.status = r.status; throw e; }
    return d;
  }
  function backToLogin(){ me = null; curUser = null; sessionStorage.removeItem('inv_session'); renderLogin(); document.getElementById('login-screen').style.display='flex'; document.getElementById('app-root').style.display='none'; }

  // ---------- طبقة التخزين ----------
  window.idbGet = async function(store){
    if(store === 'users') return DB.users || [];
    const r = await api('GET', '/api/data/'+store);
    if(r.status === 401){ backToLogin(); return []; }
    if(!r.ok) return [];
    revs[store] = r.headers.get('X-Rev') || '0';
    const d = await r.json(); return Array.isArray(d) ? d : [];
  };
  window.idbSet = async function(store, value){
    const r = await api('PUT', '/api/data/'+store, JSON.stringify(value), {'If-Match': revs[store] === undefined ? '0' : revs[store]});
    if(r.status === 401){ backToLogin(); throw new Error('انتهت الجلسة'); }
    const d = await r.json().catch(()=>({}));
    if(!r.ok){ const e = new Error(d.error || 'تعذر الحفظ'); e.status = r.status; throw e; }
    revs[store] = String(d.rev); return true;
  };
  window.idbClear = async function(store){ return window.idbSet(store, []); };
  window.loadDB = async function(){
    await Promise.all(STORES.filter(k=>k!=='users').map(async k=>{ try{ DB[k] = await window.idbGet(k); }catch(e){ DB[k] = []; } }));
    DB.users = [];
    if(me && me.admin){ try{ const d = await jsonOrErr(await api('GET','/api/users')); DB.users = d.users.filter(u=>!u.admin); }catch(e){} }
  };
  window.saveDB = async function(k){
    if(k === 'users') return true;                       // المستخدمون يُحفظون عبر واجهة /api/users
    if(typeof canSaveStore==='function' && !canSaveStore(k)) return false;
    _expCache = null;
    try{ await window.idbSet(k, DB[k]); return true; }
    catch(e){
      console.error('save failed', k, e);
      uiAlert(e.status === 409 ? e.message : ('تعذر الحفظ على الخادم: '+e.message));
      return false;
    }
  };
  window.resetAll = async function(){
    if(!(await uiConfirm('سيتم حذف جميع البيانات المستوردة من الخادم نهائيًا (لن تتأثر حسابات المستخدمين). متابعة؟', {danger:true, okText:'حذف كل البيانات'}))) return;
    try{ await jsonOrErr(await api('POST','/api/reset',{})); }catch(e){ uiAlert('تعذر الحذف: '+e.message); return; }
    for(const k of BACKUP_STORES){ DB[k] = []; revs[k] = undefined; }
    await window.loadDB(); render(); alert('تم حذف جميع البيانات من الخادم بنجاح.');
  };

  // ---------- الدخول والمستخدمون ----------
  window.ownerName = function(){ return (me && me.admin) ? me.username : ''; };
  window.resolveCurrentUser = function(){
    if(!me) return false;
    curUser = {id:me.id, name:me.name, username:me.username, admin:me.admin, perms:me.perms||{}}; return true;
  };
  window.renderLogin = async function(){
    const box = document.getElementById('login-screen');
    let needsSetup = false; try{ needsSetup = (await (await fetch('/api/status')).json()).needsSetup; }catch(e){}
    const lg = `<div class="logo"><svg width="52" height="52" viewBox="0 0 40 40" fill="none"><rect width="40" height="40" rx="9" fill="#C9A876"/><path d="M20 7l10 5.5v11L20 29l-10-5.5v-11L20 7z" stroke="#0B1F3D" stroke-width="1.6"/><path d="M10 12.5L20 18l10-5.5M20 18v11" stroke="#0B1F3D" stroke-width="1.6"/></svg></div>`;
    if(needsSetup){
      box.innerHTML = `<div class="login-box">${lg}<h2>إعداد النظام</h2>
        <div class="hint">أول تشغيل — أنشئ حساب مدير النظام (كلمة المرور 8 أحرف فأكثر).</div><div class="err" id="auth-err"></div>
        <input id="su-user" placeholder="اسم المستخدم" autocomplete="username"><input id="su-pass" type="password" placeholder="كلمة المرور" autocomplete="new-password">
        <input id="su-pass2" type="password" placeholder="تأكيد كلمة المرور" autocomplete="new-password">
        <button class="btn" onclick="doSignup()">إنشاء حساب المدير والدخول</button></div>`;
    }else{
      box.innerHTML = `<div class="login-box">${lg}<h2>تسجيل الدخول</h2>
        <div class="hint">نظام مراقبة المخزون<br><span style="color:var(--gold-d);font-weight:600">المطور: باسم الحذيفي</span></div><div class="err" id="auth-err"></div>
        <input id="li-user" placeholder="اسم المستخدم" autocomplete="username"><input id="li-pass" type="password" placeholder="كلمة المرور" autocomplete="current-password"
          onkeydown="if(event.key==='Enter')doLogin()"><button class="btn" onclick="doLogin()">دخول</button></div>`;
    }
  };
  window.doSignup = async function(){
    const u = document.getElementById('su-user').value.trim(), p = document.getElementById('su-pass').value, p2 = document.getElementById('su-pass2').value;
    const err = document.getElementById('auth-err');
    if(!u || !p){ err.textContent='الرجاء تعبئة جميع الحقول'; return; }
    if(p !== p2){ err.textContent='كلمتا المرور غير متطابقتين'; return; }
    try{ await jsonOrErr(await api('POST','/api/setup',{username:u, password:p, name:u})); boot(); }catch(e){ err.textContent = e.message; }
  };
  window.doLogin = async function(){
    const u = document.getElementById('li-user').value.trim(), p = document.getElementById('li-pass').value;
    try{ await jsonOrErr(await api('POST','/api/login',{username:u, password:p})); boot(); }
    catch(e){ document.getElementById('auth-err').textContent = e.message; }
  };
  window.logout = async function(){ try{ await api('POST','/api/logout',{}); }catch(e){} me = null; curUser = null; sessionStorage.removeItem('inv_session'); boot(); };
  window.boot = async function(){
    let r; try{ r = await api('GET','/api/me'); }catch(e){ r = null; }
    me = (r && r.ok) ? (await r.json()).user : null;
    const logged = !!me;
    document.getElementById('login-screen').style.display = logged ? 'none' : 'flex';
    document.getElementById('app-root').style.display = logged ? 'block' : 'none';
    if(!logged){ renderLogin(); return; }
    sessionStorage.setItem('inv_session','1');
    resolveCurrentUser();
    await window.loadDB();
    installPermGuards();
    if(!can(activeTab,'v')) activeTab = firstViewableTab();
    render();
  };

  // مستخدمو النظام: الحفظ على الخادم
  function permsClean(d){ const perms = {}; for(const t of TABS){ if(t.id==='users') continue; const p = d.perms[t.id]; if(p && (p.v||p.e||p.x)) perms[t.id] = {v:p.v?1:0, e:p.e?1:0, x:p.x?1:0}; } return perms; }
  window.usrSave = async function(){
    const d = usrEdit; if(!d) return;
    const uname = d.username.trim();
    if(!uname){ uiAlert('أدخل اسم المستخدم.'); return; }
    if(!/^[A-Za-z0-9_.\-@؀-ۿ]+$/.test(uname)){ uiAlert('اسم المستخدم يقبل الحروف والأرقام والرموز _ . - @ فقط (بدون مسافات).'); return; }
    if(!d.id && d.password.length<6){ uiAlert('كلمة المرور يجب ألا تقل عن 6 أحرف.'); return; }
    if(d.id && d.password && d.password.length<6){ uiAlert('كلمة المرور الجديدة يجب ألا تقل عن 6 أحرف.'); return; }
    const body = {username:uname, name:d.name.trim()||uname, active:d.active, perms:permsClean(d)}; if(d.password) body.password = d.password;
    try{
      await jsonOrErr(await api(d.id?'PUT':'POST', d.id?('/api/users/'+d.id):'/api/users', body));
      const wasNew = !d.id; usrEdit = null; await window.loadDB(); render();
      uiAlert(wasNew ? 'تمت إضافة المستخدم وحفظ صلاحياته ✅' : 'تم حفظ التعديلات ✅');
    }catch(e){ uiAlert(e.message); }
  };
  window.usrToggle = async function(id){
    const u = DB.users.find(x=>x.id===id); if(!u) return;
    try{ await jsonOrErr(await api('PUT','/api/users/'+id,{username:u.username, name:u.name, active:u.active===false, perms:u.perms})); await window.loadDB(); render(); }catch(e){ uiAlert(e.message); }
  };
  window.usrDelete = async function(id){
    const u = DB.users.find(x=>x.id===id); if(!u) return;
    if(!(await uiConfirm('سيتم حذف المستخدم «'+(u.name||u.username)+'» نهائيًا. متابعة؟', {danger:true, okText:'حذف المستخدم'}))) return;
    try{ await jsonOrErr(await api('DELETE','/api/users/'+id)); await window.loadDB(); render(); }catch(e){ uiAlert(e.message); }
  };
  boot();
})();
