/* ====================================================================
   WORKER DU HUB KINVOS
   - Sert le site statique (dossier /public, via env.ASSETS)
   - Comptes clients : téléphone + code choisi par le client (pas d'e-mail
     obligatoire, pas d'OTP). Permet de se reconnecter depuis n'importe
     quel appareil et de retrouver ses logiciels achetés.
   - POST /api/generate-licence  : génère un code licence "KVS-..." après
     un achat, l'attache au compte du client, et le stocke pour l'admin.
     -> Pas encore relié à Fedapay : appelable directement depuis le site
        pour que tu puisses tout vérifier toi-même avant de brancher le
        vrai paiement (cf. commentaire plus bas).
   - GET  /api/admin/licences    : liste les licences générées, protégé
     par mot de passe (ADMIN_PASSWORD, à définir avec wrangler secret put).
   ==================================================================== */

/* Même algorithme de signature que dans chaque logiciel (voir app.js
   d'EasyTailor : licenceSignature). Un code KVS-<TYPE>-<EXP>-<SIG> n'est
   valide QUE dans le logiciel dont le secret correspond : chaque logiciel
   a son propre secret, dérivé de son identifiant. Convention à respecter
   quand tu branches un nouveau logiciel : dans son app.js, régler
   HUB_LICENCE_SECRET = HUB_SECRET_PREFIX + '-' + ID_LOGICIEL_EN_MAJUSCULES */
const HUB_SECRET_PREFIX = 'KINVOS-HUB-2026-Cle-Commune-Ne-Pas-Diffuser';

function secretPourLogiciel(softwareId){
  return `${HUB_SECRET_PREFIX}-${String(softwareId).toUpperCase()}`;
}

async function sha256Hex(str){
  const buf = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(str));
  return Array.from(new Uint8Array(buf)).map(b => b.toString(16).padStart(2, '0')).join('');
}
async function signature(type, exp, softwareId){
  const hex = await sha256Hex(`${type}|${exp}|${secretPourLogiciel(softwareId)}`);
  return hex.slice(0, 10).toUpperCase();
}

// Formules de licence -> type (M/A/I/P) + date d'expiration AAAAMMJJ
function calculerTypeEtExpiration(planId){
  const now = new Date();
  const pad = n => String(n).padStart(2, '0');
  const fmt = d => `${d.getFullYear()}${pad(d.getMonth() + 1)}${pad(d.getDate())}`;
  if (planId === 'mensuel') {
    const d = new Date(now); d.setMonth(d.getMonth() + 1);
    return { type: 'M', exp: fmt(d) };
  }
  if (planId === 'annuel') {
    const d = new Date(now); d.setFullYear(d.getFullYear() + 1);
    return { type: 'A', exp: fmt(d) };
  }
  if (planId === 'quinquennal') {
    const d = new Date(now); d.setFullYear(d.getFullYear() + 5);
    return { type: 'P', exp: fmt(d) };
  }
  // illimité
  return { type: 'I', exp: '99991231' };
}

// Prix par formule (doit rester synchronisé avec le tableau PLANS du front)
const PRIX_PAR_PLAN = { mensuel: 1600, annuel: 12000, quinquennal: 40000, illimite: 80000 };

// Numéro de quittance global, incrémenté à chaque achat sur la plateforme,
// tous logiciels confondus (ex: KVS-2026-000001, KVS-2026-000002, ...).
// Basé sur KV : suffisant pour le volume actuel, mais deux achats à la
// même milliseconde exacte pourraient en théorie obtenir le même numéro
// (risque négligeable en pratique, à surveiller si le trafic grossit).
async function prochainNumeroFacture(env){
  const annee = new Date().getFullYear();
  const cle = `compteur:factures:${annee}`;
  const actuel = parseInt((await env.LICENCES.get(cle)) || '0', 10);
  const suivant = actuel + 1;
  await env.LICENCES.put(cle, String(suivant));
  return `KVS-${annee}-${String(suivant).padStart(6, '0')}`;
}

function jsonResponse(data, status = 200){
  return new Response(JSON.stringify(data), {
    status,
    headers: { 'Content-Type': 'application/json; charset=utf-8' }
  });
}

async function verifierMotDePasseAdmin(request, env){
  // ⚠️ Tant qu'aucun secret ADMIN_PASSWORD n'est défini sur Cloudflare
  // (wrangler secret put ADMIN_PASSWORD), l'espace admin reste OUVERT
  // sans mot de passe, pour permettre les vérifications initiales.
  // Dès qu'un ADMIN_PASSWORD est configuré, la vérification stricte
  // reprend automatiquement — pense à en définir un avant la mise en
  // ligne réelle du site, sinon n'importe qui peut ouvrir /admin/.
  if (!env.ADMIN_PASSWORD) return true;
  const fourni = request.headers.get('X-Admin-Password') || '';
  return fourni === env.ADMIN_PASSWORD;
}

/* ===== Comptes clients (téléphone + code) ===== */
function normaliserTelephone(tel){
  return String(tel || '').replace(/[^\d+]/g, '');
}
async function hasherCode(code, telephone){
  const enc = new TextEncoder();
  const keyMaterial = await crypto.subtle.importKey('raw', enc.encode(code), 'PBKDF2', false, ['deriveBits']);
  const bits = await crypto.subtle.deriveBits(
    { name: 'PBKDF2', salt: enc.encode('kinvos-sel-' + telephone), iterations: 100000, hash: 'SHA-256' },
    keyMaterial, 256
  );
  return Array.from(new Uint8Array(bits)).map(b => b.toString(16).padStart(2, '0')).join('');
}
function creerToken(){
  return crypto.randomUUID().replace(/-/g, '');
}
const DUREE_SESSION_SECONDES = 60 * 60 * 24 * 60; // 60 jours

/* ===== Envoi WhatsApp (API Cloud Meta) =====
   Nécessite deux secrets Cloudflare, à définir une fois le compte WhatsApp
   Business Cloud API prêt (business.facebook.com) :
     npx wrangler secret put WHATSAPP_TOKEN        (jeton d'accès permanent)
     npx wrangler secret put WHATSAPP_PHONE_ID      (ID du numéro expéditeur)
   Tant que ces secrets ne sont pas définis, les messages du formulaire
   "Nous contacter" restent quand même enregistrés et visibles immédiatement
   dans l'onglet "Messages" de l'espace admin — rien n'est perdu, seul
   l'envoi automatique vers ton WhatsApp est alors désactivé. */
const WHATSAPP_ADMIN_NUMERO = '22966661846'; // ton numéro, sans "+" ni espaces

async function envoyerWhatsApp(env, texte){
  if (!env.WHATSAPP_TOKEN || !env.WHATSAPP_PHONE_ID) {
    return { envoye: false, raison: 'WHATSAPP_TOKEN / WHATSAPP_PHONE_ID non configurés.' };
  }
  try {
    const res = await fetch(`https://graph.facebook.com/v20.0/${env.WHATSAPP_PHONE_ID}/messages`, {
      method: 'POST',
      headers: {
        'Authorization': `Bearer ${env.WHATSAPP_TOKEN}`,
        'Content-Type': 'application/json'
      },
      body: JSON.stringify({
        messaging_product: 'whatsapp',
        to: WHATSAPP_ADMIN_NUMERO,
        type: 'text',
        text: { body: texte }
      })
    });
    const data = await res.json().catch(() => ({}));
    if (!res.ok) return { envoye: false, raison: data?.error?.message || `Erreur HTTP ${res.status}` };
    return { envoye: true };
  } catch (e) {
    return { envoye: false, raison: String(e) };
  }
}

async function compteDepuisToken(request, env){
  const token = request.headers.get('X-Session-Token') || '';
  if (!token) return null;
  const telephone = await env.COMPTES.get(`session:${token}`);
  if (!telephone) return null;
  const raw = await env.COMPTES.get(`compte:${telephone}`);
  return raw ? JSON.parse(raw) : null;
}

export default {
  async fetch(request, env){
    const url = new URL(request.url);

    // ---------- Créer un compte client (téléphone + code choisi) ----------
    if (url.pathname === '/api/compte/creer' && request.method === 'POST') {
      let body; try { body = await request.json(); } catch (e) { return jsonResponse({ error: 'JSON invalide' }, 400); }
      const telephone = normaliserTelephone(body?.telephone);
      const code = String(body?.code || '');
      if (!telephone || code.length < 4) return jsonResponse({ error: 'Numéro et code (4 caractères minimum) requis.' }, 400);
      const existant = await env.COMPTES.get(`compte:${telephone}`);
      if (existant) return jsonResponse({ error: 'Ce numéro a déjà un compte. Connectez-vous plutôt.' }, 409);
      const compte = {
        telephone, nom: body?.nom || '', email: body?.email || '', org: body?.org || '',
        codeHash: await hasherCode(code, telephone), purchases: [], creeLe: new Date().toISOString()
      };
      await env.COMPTES.put(`compte:${telephone}`, JSON.stringify(compte));
      const token = creerToken();
      await env.COMPTES.put(`session:${token}`, telephone, { expirationTtl: DUREE_SESSION_SECONDES });
      const { codeHash, ...compteSansHash } = compte;
      return jsonResponse({ ok: true, token, compte: compteSansHash });
    }

    // ---------- Se connecter (téléphone + code) ----------
    if (url.pathname === '/api/compte/connecter' && request.method === 'POST') {
      let body; try { body = await request.json(); } catch (e) { return jsonResponse({ error: 'JSON invalide' }, 400); }
      const telephone = normaliserTelephone(body?.telephone);
      const code = String(body?.code || '');
      const raw = await env.COMPTES.get(`compte:${telephone}`);
      if (!raw) return jsonResponse({ error: 'Aucun compte avec ce numéro.' }, 404);
      const compte = JSON.parse(raw);
      const hash = await hasherCode(code, telephone);
      if (hash !== compte.codeHash) return jsonResponse({ error: 'Code incorrect.' }, 401);
      const token = creerToken();
      await env.COMPTES.put(`session:${token}`, telephone, { expirationTtl: DUREE_SESSION_SECONDES });
      const { codeHash, ...compteSansHash } = compte;
      return jsonResponse({ ok: true, token, compte: compteSansHash });
    }

    // ---------- Mon compte (via token de session) ----------
    if (url.pathname === '/api/compte/moi' && request.method === 'GET') {
      const compte = await compteDepuisToken(request, env);
      if (!compte) return jsonResponse({ error: 'Session invalide.' }, 401);
      const { codeHash, ...compteSansHash } = compte;
      return jsonResponse({ ok: true, compte: compteSansHash });
    }

    // ---------- Modifier mes informations personnelles ----------
    if (url.pathname === '/api/compte/modifier' && request.method === 'POST') {
      const compte = await compteDepuisToken(request, env);
      if (!compte) return jsonResponse({ error: 'Session invalide.' }, 401);
      let body; try { body = await request.json(); } catch (e) { return jsonResponse({ error: 'JSON invalide' }, 400); }
      const nom = String(body?.nom || '').trim();
      const email = String(body?.email || '').trim();
      const org = String(body?.org || '').trim();
      if (!nom) return jsonResponse({ error: 'Le nom complet est requis.' }, 400);
      compte.nom = nom;
      compte.email = email;
      compte.org = org;
      await env.COMPTES.put(`compte:${compte.telephone}`, JSON.stringify(compte));
      const { codeHash, ...compteSansHash } = compte;
      return jsonResponse({ ok: true, compte: compteSansHash });
    }

    // ---------- Générer une licence après achat ----------
    // ⚠️ Bypass Fedapay temporaire : appelable directement, sans preuve de
    // paiement, pour que tu puisses vérifier tout le circuit toi-même.
    // Avant l'ouverture au public, brancher un vrai webhook Fedapay ici
    // (vérifier la signature Fedapay, PUIS générer la licence).
    if (url.pathname === '/api/generate-licence' && request.method === 'POST') {
      const compte = await compteDepuisToken(request, env);
      if (!compte) return jsonResponse({ error: 'Connectez-vous avant d\'acheter.' }, 401);
      let body; try { body = await request.json(); } catch (e) { return jsonResponse({ error: 'JSON invalide' }, 400); }
      const { softwareId, planId } = body || {};
      if (!softwareId || !planId) return jsonResponse({ error: 'softwareId et planId requis' }, 400);

      const { type, exp } = calculerTypeEtExpiration(planId);
      const sig = await signature(type, exp, softwareId);
      const code = `KVS-${type}-${exp}-${sig}`;
      const factureNumero = await prochainNumeroFacture(env);
      const prix = PRIX_PAR_PLAN[planId] ?? null;

      const id = `${Date.now()}-${Math.random().toString(36).slice(2, 8)}`;
      const record = {
        id, code, softwareId, planId, type, exp,
        factureNumero, prix,
        clientNom: compte.nom, clientEmail: compte.email,
        clientTelephone: compte.telephone, organisation: compte.org,
        statut: 'test', // deviendra 'payé' une fois Fedapay branché
        actif: true, // peut être désactivée manuellement depuis l'espace admin
        creeLe: new Date().toISOString()
      };
      await env.LICENCES.put(`lic:${id}`, JSON.stringify(record));

      // Attache l'achat au compte pour qu'il apparaisse dans "Mon compte"
      // depuis n'importe quel appareil après connexion.
      const compteRaw = await env.COMPTES.get(`compte:${compte.telephone}`);
      const compteAJour = JSON.parse(compteRaw);
      compteAJour.purchases = (compteAJour.purchases || []).filter(p => p.softwareId !== softwareId);
      compteAJour.purchases.push({ softwareId, planId, code, type, exp, factureNumero, prix, actif: true, dateAchat: new Date().toISOString() });
      await env.COMPTES.put(`compte:${compte.telephone}`, JSON.stringify(compteAJour));

      return jsonResponse({ ok: true, code, record });
    }

    // ---------- Formulaire "Nous contacter" : envoi direct vers le WhatsApp de KINVOS ----------
    // Le message est TOUJOURS enregistré côté serveur (visible aussitôt dans l'onglet
    // "Messages" de l'espace admin), et une tentative d'envoi WhatsApp automatique est
    // faite si les secrets WHATSAPP_TOKEN / WHATSAPP_PHONE_ID sont configurés.
    if (url.pathname === '/api/contact' && request.method === 'POST') {
      let body; try { body = await request.json(); } catch (e) { return jsonResponse({ error: 'JSON invalide' }, 400); }
      const nom = String(body?.nom || '').trim();
      const email = String(body?.email || '').trim();
      const whatsapp = normaliserTelephone(body?.whatsapp);
      const logiciel = String(body?.logiciel || '').trim();
      const message = String(body?.message || '').trim();
      if (!nom || !whatsapp) return jsonResponse({ error: 'Nom et numéro WhatsApp requis.' }, 400);

      const texte = [
        '📩 Nouveau message depuis le site Hub Les Logiciels Easy',
        `Nom : ${nom}`,
        email ? `E-mail : ${email}` : null,
        `WhatsApp : +${whatsapp}`,
        logiciel ? `Logiciel concerné : ${logiciel}` : null,
        message ? `Message : ${message}` : null,
      ].filter(Boolean).join('\n');

      const resultat = await envoyerWhatsApp(env, texte);

      const id = `${Date.now()}-${Math.random().toString(36).slice(2, 8)}`;
      const enregistrement = {
        id, nom, email, whatsapp, logiciel, message,
        envoyeWhatsApp: resultat.envoye, raisonEchec: resultat.envoye ? null : resultat.raison,
        creeLe: new Date().toISOString()
      };
      await env.COMPTES.put(`msg:${id}`, JSON.stringify(enregistrement));

      return jsonResponse({ ok: true, envoyeWhatsApp: resultat.envoye });
    }

    // ---------- Espace admin : liste des messages du formulaire de contact ----------
    if (url.pathname === '/api/admin/messages' && request.method === 'GET') {
      if (!(await verifierMotDePasseAdmin(request, env))) return jsonResponse({ error: 'Mot de passe invalide' }, 401);
      const liste = await env.COMPTES.list({ prefix: 'msg:' });
      const messages = await Promise.all(liste.keys.map(async k => {
        const v = await env.COMPTES.get(k.name);
        return v ? JSON.parse(v) : null;
      }));
      const propres = messages.filter(Boolean).sort((a, b) => (a.creeLe < b.creeLe ? 1 : -1));
      return jsonResponse({ ok: true, messages: propres });
    }

    // ---------- Espace admin : activer / désactiver une licence ----------
    if (url.pathname === '/api/admin/licence/actif' && request.method === 'POST') {
      if (!(await verifierMotDePasseAdmin(request, env))) return jsonResponse({ error: 'Mot de passe invalide' }, 401);
      let body; try { body = await request.json(); } catch (e) { return jsonResponse({ error: 'JSON invalide' }, 400); }
      const { id, actif } = body || {};
      if (!id || typeof actif !== 'boolean') return jsonResponse({ error: 'id et actif (booléen) requis' }, 400);
      const raw = await env.LICENCES.get(`lic:${id}`);
      if (!raw) return jsonResponse({ error: 'Licence introuvable.' }, 404);
      const licence = JSON.parse(raw);
      licence.actif = actif;
      await env.LICENCES.put(`lic:${id}`, JSON.stringify(licence));

      // Répercute l'état sur le compte client, pour que "Mon compte" reflète le changement.
      if (licence.clientTelephone) {
        const compteRaw = await env.COMPTES.get(`compte:${licence.clientTelephone}`);
        if (compteRaw) {
          const compte = JSON.parse(compteRaw);
          const achat = (compte.purchases || []).find(p => p.softwareId === licence.softwareId && p.code === licence.code);
          if (achat) {
            achat.actif = actif;
            await env.COMPTES.put(`compte:${licence.clientTelephone}`, JSON.stringify(compte));
          }
        }
      }
      return jsonResponse({ ok: true, licence });
    }

    // ---------- Espace admin : renouveler manuellement une licence ----------
    if (url.pathname === '/api/admin/licence/renouveler' && request.method === 'POST') {
      if (!(await verifierMotDePasseAdmin(request, env))) return jsonResponse({ error: 'Mot de passe invalide' }, 401);
      let body; try { body = await request.json(); } catch (e) { return jsonResponse({ error: 'JSON invalide' }, 400); }
      const { id, planId } = body || {};
      if (!id || !planId) return jsonResponse({ error: 'id et planId requis' }, 400);
      const raw = await env.LICENCES.get(`lic:${id}`);
      if (!raw) return jsonResponse({ error: 'Licence introuvable.' }, 404);
      const licence = JSON.parse(raw);

      const { type, exp } = calculerTypeEtExpiration(planId);
      const sig = await signature(type, exp, licence.softwareId);
      const nouveauCode = `KVS-${type}-${exp}-${sig}`;
      const nouvelleFacture = await prochainNumeroFacture(env);
      const nouveauPrix = PRIX_PAR_PLAN[planId] ?? licence.prix;
      const ancienCode = licence.code;

      Object.assign(licence, {
        planId, type, exp, code: nouveauCode,
        factureNumero: nouvelleFacture, prix: nouveauPrix,
        actif: true, renouveleLe: new Date().toISOString()
      });
      await env.LICENCES.put(`lic:${id}`, JSON.stringify(licence));

      if (licence.clientTelephone) {
        const compteRaw = await env.COMPTES.get(`compte:${licence.clientTelephone}`);
        if (compteRaw) {
          const compte = JSON.parse(compteRaw);
          const achat = (compte.purchases || []).find(p => p.softwareId === licence.softwareId && p.code === ancienCode);
          if (achat) {
            Object.assign(achat, { planId, type, exp, code: nouveauCode, factureNumero: nouvelleFacture, prix: nouveauPrix, actif: true, dateAchat: new Date().toISOString() });
          } else {
            compte.purchases = compte.purchases || [];
            compte.purchases.push({ softwareId: licence.softwareId, planId, type, exp, code: nouveauCode, factureNumero: nouvelleFacture, prix: nouveauPrix, actif: true, dateAchat: new Date().toISOString() });
          }
          await env.COMPTES.put(`compte:${licence.clientTelephone}`, JSON.stringify(compte));
        }
      }
      return jsonResponse({ ok: true, licence });
    }

    // ---------- Espace admin : modifier les informations d'un client ----------
    if (url.pathname === '/api/admin/compte/modifier' && request.method === 'POST') {
      if (!(await verifierMotDePasseAdmin(request, env))) return jsonResponse({ error: 'Mot de passe invalide' }, 401);
      let body; try { body = await request.json(); } catch (e) { return jsonResponse({ error: 'JSON invalide' }, 400); }
      const telephone = normaliserTelephone(body?.telephone);
      if (!telephone) return jsonResponse({ error: 'telephone requis' }, 400);
      const compteRaw = await env.COMPTES.get(`compte:${telephone}`);
      if (!compteRaw) return jsonResponse({ error: 'Compte introuvable.' }, 404);
      const compte = JSON.parse(compteRaw);
      if (body.nom !== undefined) compte.nom = String(body.nom).trim();
      if (body.email !== undefined) compte.email = String(body.email).trim();
      if (body.org !== undefined) compte.org = String(body.org).trim();
      await env.COMPTES.put(`compte:${telephone}`, JSON.stringify(compte));
      const { codeHash, ...compteSansHash } = compte;
      return jsonResponse({ ok: true, compte: compteSansHash });
    }

    // ---------- Espace admin : liste des comptes clients ----------
    if (url.pathname === '/api/admin/comptes' && request.method === 'GET') {
      if (!(await verifierMotDePasseAdmin(request, env))) return jsonResponse({ error: 'Mot de passe invalide' }, 401);
      const liste = await env.COMPTES.list({ prefix: 'compte:' });
      const comptes = await Promise.all(liste.keys.map(async k => {
        const v = await env.COMPTES.get(k.name);
        if (!v) return null;
        const { codeHash, ...sansHash } = JSON.parse(v);
        return sansHash;
      }));
      const propres = comptes.filter(Boolean).sort((a, b) => (a.creeLe < b.creeLe ? 1 : -1));
      return jsonResponse({ ok: true, comptes: propres });
    }

    // ---------- Espace admin : liste des licences ----------
    if (url.pathname === '/api/admin/licences' && request.method === 'GET') {
      if (!(await verifierMotDePasseAdmin(request, env))) return jsonResponse({ error: 'Mot de passe invalide' }, 401);
      const liste = await env.LICENCES.list({ prefix: 'lic:' });
      const enregistrements = await Promise.all(liste.keys.map(async k => {
        const v = await env.LICENCES.get(k.name);
        return v ? JSON.parse(v) : null;
      }));
      const propres = enregistrements.filter(Boolean).sort((a, b) => (a.creeLe < b.creeLe ? 1 : -1));
      return jsonResponse({ ok: true, licences: propres });
    }

    // ---------- Vérifier le mot de passe admin (pour l'écran de connexion) ----------
    if (url.pathname === '/api/admin/verifier' && request.method === 'POST') {
      const ok = await verifierMotDePasseAdmin(request, env);
      return jsonResponse({ ok });
    }

    // ---------- Sinon : fichiers statiques (site public + /admin) ----------
    return env.ASSETS.fetch(request);
  }
};
