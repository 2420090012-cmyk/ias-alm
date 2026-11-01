from flask import Flask, request, jsonify
from flask_cors import CORS
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography import x509
from cryptography.x509.oid import NameOID
from datetime import datetime, timedelta, timezone
import base64, hashlib, ipaddress, json, os, secrets, sqlite3, statistics, time

app = Flask(__name__)
CORS(app)
DB = os.path.join(os.path.dirname(__file__), 'cipherguard.db')


def db():
    con = sqlite3.connect(DB)
    con.row_factory = sqlite3.Row
    return con


def init_db():
    with db() as con:
        con.execute('''CREATE TABLE IF NOT EXISTS firewall_rules (
            id INTEGER PRIMARY KEY AUTOINCREMENT, source TEXT NOT NULL DEFAULT '*',
            destination TEXT NOT NULL DEFAULT '*', port TEXT NOT NULL DEFAULT '*',
            protocol TEXT NOT NULL DEFAULT 'ANY', action TEXT NOT NULL CHECK(action IN ('ALLOW','BLOCK')),
            created_at TEXT DEFAULT CURRENT_TIMESTAMP)''')
        con.execute('''CREATE TABLE IF NOT EXISTS packet_log (
            id INTEGER PRIMARY KEY AUTOINCREMENT, source TEXT, destination TEXT, port INTEGER,
            protocol TEXT, bytes INTEGER, decision TEXT, note TEXT, created_at TEXT DEFAULT CURRENT_TIMESTAMP)''')
        con.execute('''CREATE TABLE IF NOT EXISTS alerts (
            id INTEGER PRIMARY KEY AUTOINCREMENT, severity TEXT, title TEXT, detail TEXT,
            source TEXT, created_at TEXT DEFAULT CURRENT_TIMESTAMP)''')

init_db()

@app.get('/api/health')
def health():
    return jsonify(status='online', application='CipherGuard IAS Security Lab', version='1.0')

@app.post('/api/hash')
def hash_text():
    data = request.get_json(force=True)
    text = data.get('text', '')
    algorithm = data.get('algorithm', 'sha256').lower()
    if algorithm not in ('sha256', 'sha512', 'sha3_256'):
        return jsonify(error='Supported algorithms: SHA-256, SHA-512, SHA3-256'), 400
    digest = hashlib.new(algorithm, text.encode()).hexdigest()
    return jsonify(algorithm=algorithm.upper().replace('_', '-'), digest=digest)

@app.post('/api/rsa/generate')
def rsa_generate():
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    private_pem = key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()).decode()
    public_pem = key.public_key().public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo).decode()
    return jsonify(private_key=private_pem, public_key=public_pem, warning='Demo key pair. Keep private keys secret; this demo does not store them.')

@app.post('/api/rsa/encrypt')
def rsa_encrypt():
    d = request.get_json(force=True)
    try:
        pub = serialization.load_pem_public_key(d['public_key'].encode())
        ciphertext = pub.encrypt(d.get('message','').encode(), padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None))
        return jsonify(ciphertext=base64.b64encode(ciphertext).decode())
    except Exception as e: return jsonify(error='Encryption failed. Check the public key and message length.'), 400

@app.post('/api/rsa/decrypt')
def rsa_decrypt():
    d = request.get_json(force=True)
    try:
        priv = serialization.load_pem_private_key(d['private_key'].encode(), password=None)
        plaintext = priv.decrypt(base64.b64decode(d['ciphertext']), padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None))
        return jsonify(message=plaintext.decode())
    except Exception: return jsonify(error='Decryption failed. Check that the private key matches the ciphertext.'), 400

@app.post('/api/rsa/sign')
def rsa_sign():
    d=request.get_json(force=True)
    try:
        key=serialization.load_pem_private_key(d['private_key'].encode(),password=None)
        sig=key.sign(d.get('message','').encode(),padding.PSS(mgf=padding.MGF1(hashes.SHA256()),salt_length=padding.PSS.MAX_LENGTH),hashes.SHA256())
        return jsonify(signature=base64.b64encode(sig).decode())
    except Exception: return jsonify(error='Signing failed. Check the private key.'),400

@app.post('/api/rsa/verify')
def rsa_verify():
    d=request.get_json(force=True)
    try:
        key=serialization.load_pem_public_key(d['public_key'].encode())
        key.verify(base64.b64decode(d['signature']),d.get('message','').encode(),padding.PSS(mgf=padding.MGF1(hashes.SHA256()),salt_length=padding.PSS.MAX_LENGTH),hashes.SHA256())
        return jsonify(valid=True,message='Signature is valid. Message integrity and signer possession are verified.')
    except Exception: return jsonify(valid=False,message='Invalid signature or modified message.'),200

@app.post('/api/certificate')
def certificate():
    d=request.get_json(force=True)
    try:
        key=serialization.load_pem_private_key(d['private_key'].encode(),password=None)
        subject=x509.Name([x509.NameAttribute(NameOID.COMMON_NAME,d.get('common_name','CipherGuard Demo User'))])
        cert=(x509.CertificateBuilder().subject_name(subject).issuer_name(subject).public_key(key.public_key()).serial_number(x509.random_serial_number()).not_valid_before(datetime.now(timezone.utc)).not_valid_after(datetime.now(timezone.utc)+timedelta(days=30)).add_extension(x509.BasicConstraints(ca=False,path_length=None),critical=True).sign(key,hashes.SHA256()))
        pem=cert.public_bytes(serialization.Encoding.PEM).decode()
        return jsonify(certificate=pem)
    except Exception: return jsonify(error='Certificate generation failed.'),400

@app.get('/api/dh')
def dh_demo():
    # Educational finite-field example only; not suitable for real key exchange.
    p,g=7919,5
    a,b=secrets.randbelow(100)+2,secrets.randbelow(100)+2
    A,B=pow(g,a,p),pow(g,b,p)
    return jsonify(prime=p,generator=g,alice_public=A,bob_public=B,alice_secret=pow(B,a,p),bob_secret=pow(A,b,p),warning='Small illustrative parameters only. Use a vetted protocol/library for real systems.')

@app.post('/api/elgamal')
def elgamal():
    d=request.get_json(force=True); msg=d.get('message','')
    # Teaching-only toy signature over a small prime field.
    p,g,x=7919,5,127
    y=pow(g,x,p); h=int.from_bytes(hashlib.sha256(msg.encode()).digest(),'big')%(p-1)
    k=17
    while __import__('math').gcd(k,p-1)!=1: k+=2
    r=pow(g,k,p); s=((h-x*r)*pow(k,-1,p-1))%(p-1)
    valid=(pow(g,h,p)==(pow(y,r,p)*pow(r,s,p))%p)
    return jsonify(public_key=y,r=r,s=s,valid=valid,warning='Toy ElGamal parameters for classroom demonstration only; not cryptographically secure.')

@app.get('/api/tunnel/<kind>')
def tunnel(kind):
    flows={
      'tls': [('ClientHello','Client proposes TLS version, cipher suites and key share.'),('ServerHello','Server selects parameters and sends its key share.'),('Certificate','Server presents its identity certificate.'),('Finished','Both sides verify handshake transcript and derive traffic keys.'),('Secure session','Application data is protected with symmetric authenticated encryption.')],
      'ssh': [('Version exchange','Client and server announce SSH protocol versions.'),('Algorithm negotiation','Both sides select compatible key exchange and cipher algorithms.'),('Key exchange','Ephemeral key agreement derives a shared session secret.'),('Host authentication','Client validates the server host key.'),('User authentication','User proves identity using an approved method.'),('Encrypted channel','Encrypted SSH session is established.')]
    }
    if kind not in flows: return jsonify(error='Unknown tunnel type'),404
    return jsonify(name=kind.upper(),steps=[{'step':a,'description':b} for a,b in flows[kind]])

@app.get('/api/ipsec')
def ipsec():
    return jsonify(transport={'protected':'TCP/UDP payload','visible':'Original IP header','description':'Protects the IP payload while retaining the original IP header.'},tunnel={'protected':'Original IP packet','visible':'New outer IP header','description':'Encapsulates and protects the complete original IP packet inside a new packet.'})

@app.get('/api/firewall')
def get_rules():
    with db() as con: rows=con.execute('SELECT * FROM firewall_rules ORDER BY id DESC').fetchall()
    return jsonify(rules=[dict(r) for r in rows])

@app.post('/api/firewall')
def add_rule():
    d=request.get_json(force=True); action=d.get('action','ALLOW').upper(); proto=d.get('protocol','ANY').upper()
    if action not in ('ALLOW','BLOCK') or proto not in ('ANY','TCP','UDP','ICMP'): return jsonify(error='Invalid action or protocol.'),400
    try:
        for field in ('source','destination'):
            value=d.get(field,'*')
            if value!='*': ipaddress.ip_network(value,strict=False)
        port=str(d.get('port','*'))
        if port!='*' and not (1<=int(port)<=65535): raise ValueError()
    except Exception: return jsonify(error='Use valid IP/CIDR values and a port from 1 to 65535.'),400
    with db() as con:
        cur=con.execute('INSERT INTO firewall_rules(source,destination,port,protocol,action) VALUES(?,?,?,?,?)',(d.get('source','*'),d.get('destination','*'),port,proto,action)); rid=cur.lastrowid
    return jsonify(id=rid,message='Firewall rule added.'),201

@app.delete('/api/firewall/<int:rule_id>')
def delete_rule(rule_id):
    with db() as con: cur=con.execute('DELETE FROM firewall_rules WHERE id=?',(rule_id,))
    return (jsonify(message='Rule deleted.'),200) if cur.rowcount else (jsonify(error='Rule not found.'),404)

def matches(pattern,value):
    if pattern=='*': return True
    try: return ipaddress.ip_address(value) in ipaddress.ip_network(pattern,strict=False)
    except Exception: return pattern==value

@app.post('/api/traffic')
def traffic():
    d=request.get_json(force=True); src=d.get('source','192.168.1.10'); dst=d.get('destination','10.0.0.5'); port=int(d.get('port',443)); proto=d.get('protocol','TCP').upper(); size=int(d.get('bytes',512)); failed=bool(d.get('failed_login',False))
    if not (1<=port<=65535 and 0<=size<=10000000): return jsonify(error='Invalid port or packet size.'),400
    with db() as con: rules=[dict(r) for r in con.execute('SELECT * FROM firewall_rules ORDER BY id DESC').fetchall()]
    decision='ALLOW'; matched=None
    for r in rules:
        if matches(r['source'],src) and matches(r['destination'],dst) and (r['port']=='*' or int(r['port'])==port) and (r['protocol']=='ANY' or r['protocol']==proto):
            decision=r['action']; matched=r['id']; break
    notes=[]
    if port==23: notes.append(('HIGH','Telnet traffic detected','Telnet transmits data without modern transport encryption.',src))
    if failed:
        notes.append(('MEDIUM','Failed SSH login attempt','A failed authentication event was simulated.',src))
    with db() as con:
        con.execute('INSERT INTO packet_log(source,destination,port,protocol,bytes,decision,note) VALUES(?,?,?,?,?,?,?)',(src,dst,port,proto,size,decision,f'Matched rule {matched}' if matched else 'Default policy'))
        for sev,title,detail,ip in notes: con.execute('INSERT INTO alerts(severity,title,detail,source) VALUES(?,?,?,?)',(sev,title,detail,ip))
        # Basic volume anomaly: compare current sample with recent source history.
        prior=[r['bytes'] for r in con.execute('SELECT bytes FROM packet_log WHERE source=? ORDER BY id DESC LIMIT 10 OFFSET 1',(src,)).fetchall()]
        if len(prior)>=5:
            avg=statistics.mean(prior); sd=statistics.pstdev(prior)
            if size>avg+3*max(sd,1):
                con.execute('INSERT INTO alerts(severity,title,detail,source) VALUES(?,?,?,?)',('HIGH','Traffic volume anomaly',f'{size} bytes is above the source baseline threshold ({avg+3*max(sd,1):.1f} bytes).',src))
    return jsonify(decision=decision,matched_rule=matched,alerts=[{'severity':s,'title':t,'detail':de} for s,t,de,_ in notes],message=f'Packet {decision.lower()}ed by simulator.' if decision=='ALLOW' else 'Packet blocked by simulator.')

@app.get('/api/ids/dashboard')
def dashboard():
    with db() as con:
        packets=[dict(r) for r in con.execute('SELECT * FROM packet_log ORDER BY id DESC LIMIT 30').fetchall()]
        alerts=[dict(r) for r in con.execute('SELECT * FROM alerts ORDER BY id DESC LIMIT 30').fetchall()]
        counts=dict(con.execute("SELECT decision,COUNT(*) AS n FROM packet_log GROUP BY decision").fetchall())
    return jsonify(packets=packets,alerts=alerts,counts=counts)

@app.post('/api/reset-demo')
def reset_demo():
    with db() as con:
        con.execute('DELETE FROM packet_log'); con.execute('DELETE FROM alerts'); con.execute('DELETE FROM firewall_rules')
    return jsonify(message='Demo data cleared.')

if __name__=='__main__': app.run(debug=True,port=5000)
