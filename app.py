#!/usr/bin/env python3
"""Portal Propuestas — Gestión de propuestas técnicas con SSO"""
import os
import json
import hashlib
import hmac
import shutil
from datetime import datetime, timedelta
from functools import wraps
from pathlib import Path

from flask import (
    Flask, render_template, request, redirect, url_for,
    flash, jsonify, session, send_from_directory, abort
)
from flask_sqlalchemy import SQLAlchemy
import jwt
from werkzeug.utils import secure_filename

# ── App setup ──
app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY', 'propuestas-secret-dev-9200')
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///' + os.path.join(app.root_path, 'propuestas.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['UPLOAD_FOLDER'] = os.path.join(app.root_path, 'uploads')
app.config['MAX_CONTENT_LENGTH'] = 50 * 1024 * 1024  # 50MB
ALLOWED_EXTENSIONS = {'pdf', 'docx', 'xlsx', 'pptx', 'html', 'md', 'txt', 'png', 'jpg', 'zip'}

# SSO config
SSO_SECRET = os.environ.get('SSO_SECRET', 'sso-secret-key-cambiame')
SSO_COOKIE_NAME = 'sso_token'
ALLOWED_PORTAL = 'propuestas'

db = SQLAlchemy(app)

# ══════════════════════════════════════════════════
# MODELS
# ══════════════════════════════════════════════════
class Cliente(db.Model):
    __tablename__ = 'clientes'
    id = db.Column(db.Integer, primary_key=True)
    nombre = db.Column(db.String(200), nullable=False)
    contacto = db.Column(db.String(200))
    email = db.Column(db.String(200))
    telefono = db.Column(db.String(50))
    notas = db.Column(db.Text)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    propuestas = db.relationship('Propuesta', backref='cliente', lazy='dynamic', cascade='all, delete-orphan')
    
    def to_dict(self):
        return {
            'id': self.id, 'nombre': self.nombre, 'contacto': self.contacto,
            'email': self.email, 'telefono': self.telefono, 'notas': self.notas,
            'created_at': self.created_at.isoformat() if self.created_at else '',
            'propuestas_count': self.propuestas.count()
        }

class Propuesta(db.Model):
    __tablename__ = 'propuestas'
    id = db.Column(db.Integer, primary_key=True)
    cliente_id = db.Column(db.Integer, db.ForeignKey('clientes.id'), nullable=False)
    titulo = db.Column(db.String(300), nullable=False)
    descripcion = db.Column(db.Text)
    horas_est = db.Column(db.Integer, default=0)
    presupuesto = db.Column(db.Float, default=0.0)
    estatus = db.Column(db.String(20), default='borrador')  # borrador/enviada/aprobada/rechazada
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    documentos = db.relationship('Documento', backref='propuesta', lazy='dynamic', cascade='all, delete-orphan')

    def to_dict(self):
        return {
            'id': self.id, 'cliente_id': self.cliente_id, 'titulo': self.titulo,
            'descripcion': self.descripcion, 'horas_est': self.horas_est,
            'presupuesto': self.presupuesto, 'estatus': self.estatus,
            'created_at': self.created_at.isoformat() if self.created_at else '',
            'updated_at': self.updated_at.isoformat() if self.updated_at else '',
            'docs_count': self.documentos.count(),
            'cliente_nombre': self.cliente.nombre if self.cliente else ''
        }

class Documento(db.Model):
    __tablename__ = 'documentos'
    id = db.Column(db.Integer, primary_key=True)
    propuesta_id = db.Column(db.Integer, db.ForeignKey('propuestas.id'), nullable=False)
    filename = db.Column(db.String(300), nullable=False)
    filepath = db.Column(db.String(500), nullable=False)
    tipo = db.Column(db.String(20))  # docx, pptx, xlsx, html, otros
    descripcion = db.Column(db.String(200))
    uploaded_at = db.Column(db.DateTime, default=datetime.utcnow)

    def to_dict(self):
        return {
            'id': self.id, 'propuesta_id': self.propuesta_id,
            'filename': self.filename, 'tipo': self.tipo,
            'descripcion': self.descripcion,
            'uploaded_at': self.uploaded_at.isoformat() if self.uploaded_at else ''
        }

with app.app_context():
    db.create_all()

# ══════════════════════════════════════════════════
# SSO AUTH
# ══════════════════════════════════════════════════
def decode_sso():
    token = request.cookies.get(SSO_COOKIE_NAME) or session.get('sso_token')
    if not token:
        return None
    try:
        payload = jwt.decode(token, SSO_SECRET, algorithms=['HS256'])
        # Verify this portal is allowed
        allowed = payload.get('allowed_portals', [])
        if ALLOWED_PORTAL not in allowed and 'admin' not in payload.get('role', ''):
            return None
        return payload
    except (jwt.ExpiredSignatureError, jwt.InvalidTokenError):
        return None

def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        user = decode_sso()
        if not user:
            return redirect(f'https://datacenter.hubmultiteck.io/login?next=/propuestas{request.path}')
        session['user'] = user
        return f(*args, **kwargs)
    return decorated

def role_required(*roles):
    def decorator(f):
        @wraps(f)
        def decorated(*args, **kwargs):
            user = decode_sso()
            if not user:
                return redirect(f'https://datacenter.hubmultiteck.io/login?next=/propuestas{request.path}')
            user_role = user.get('role', '')
            if user_role not in roles and 'superadmin' not in user.get('allowed_portals', []):
                if 'admin' not in user_role:
                    abort(403)
            return f(*args, **kwargs)
        return decorated
    return decorator

@app.context_processor
def inject_user():
    user = session.get('user') or decode_sso()
    return dict(current_user=user)

@app.route('/logout')
def logout():
    session.clear()
    return redirect('https://datacenter.hubmultiteck.io/logout')

# ══════════════════════════════════════════════════
# ROUTES — Clientes
# ══════════════════════════════════════════════════
@app.route('/')
@login_required
def index():
    return redirect(url_for('dashboard'))

@app.route('/dashboard')
@login_required
def dashboard():
    q = request.args.get('q', '')
    clientes = Cliente.query.order_by(Cliente.nombre)
    if q:
        clientes = clientes.filter(Cliente.nombre.ilike(f'%{q}%'))
    clientes = clientes.all()
    stats = {
        'total_clientes': Cliente.query.count(),
        'total_propuestas': Propuesta.query.count(),
        'activas': Propuesta.query.filter(Propuesta.estatus.in_(['borrador', 'enviada'])).count(),
        'aprobadas': Propuesta.query.filter_by(estatus='aprobada').count(),
    }
    return render_template('dashboard.html', clientes=clientes, stats=stats, q=q)

@app.route('/clientes/nuevo', methods=['GET', 'POST'])
@login_required
def nuevo_cliente():
    if request.method == 'POST':
        c = Cliente(
            nombre=request.form['nombre'],
            contacto=request.form.get('contacto', ''),
            email=request.form.get('email', ''),
            telefono=request.form.get('telefono', ''),
            notas=request.form.get('notas', '')
        )
        db.session.add(c)
        db.session.commit()
        flash('Cliente creado exitosamente', 'success')
        return redirect(url_for('ver_cliente', cliente_id=c.id))
    return render_template('cliente_form.html', cliente=None)

@app.route('/clientes/<int:cliente_id>')
@login_required
def ver_cliente(cliente_id):
    c = Cliente.query.get_or_404(cliente_id)
    propuestas = c.propuestas.order_by(Propuesta.updated_at.desc()).all()
    return render_template('cliente.html', cliente=c, propuestas=propuestas)

@app.route('/clientes/<int:cliente_id>/editar', methods=['GET', 'POST'])
@login_required
def editar_cliente(cliente_id):
    c = Cliente.query.get_or_404(cliente_id)
    if request.method == 'POST':
        c.nombre = request.form['nombre']
        c.contacto = request.form.get('contacto', '')
        c.email = request.form.get('email', '')
        c.telefono = request.form.get('telefono', '')
        c.notas = request.form.get('notas', '')
        db.session.commit()
        flash('Cliente actualizado', 'success')
        return redirect(url_for('ver_cliente', cliente_id=c.id))
    return render_template('cliente_form.html', cliente=c)

@app.route('/clientes/<int:cliente_id>/eliminar', methods=['POST'])
@login_required
def eliminar_cliente(cliente_id):
    c = Cliente.query.get_or_404(cliente_id)
    db.session.delete(c)
    db.session.commit()
    flash('Cliente eliminado', 'success')
    return redirect(url_for('dashboard'))

# ══════════════════════════════════════════════════
# ROUTES — Propuestas
# ══════════════════════════════════════════════════
@app.route('/clientes/<int:cliente_id>/propuestas/nueva', methods=['GET', 'POST'])
@login_required
def nueva_propuesta(cliente_id):
    c = Cliente.query.get_or_404(cliente_id)
    if request.method == 'POST':
        p = Propuesta(
            cliente_id=cliente_id,
            titulo=request.form['titulo'],
            descripcion=request.form.get('descripcion', ''),
            horas_est=int(request.form.get('horas_est', 0)),
            presupuesto=float(request.form.get('presupuesto', 0)),
            estatus=request.form.get('estatus', 'borrador')
        )
        db.session.add(p)
        db.session.commit()

        # Handle file uploads
        files = request.files.getlist('documentos')
        for f in files:
            if f and f.filename and allowed_file(f.filename):
                guardar_documento(p.id, f)

        flash('Propuesta creada', 'success')
        return redirect(url_for('ver_propuesta', propuesta_id=p.id))
    return render_template('propuesta_form.html', cliente=c, propuesta=None)

@app.route('/propuestas/<int:propuesta_id>')
@login_required
def ver_propuesta(propuesta_id):
    p = Propuesta.query.get_or_404(propuesta_id)
    docs = p.documentos.order_by(Documento.uploaded_at.desc()).all()
    return render_template('propuesta.html', propuesta=p, documentos=docs)

@app.route('/propuestas/<int:propuesta_id>/editar', methods=['GET', 'POST'])
@login_required
def editar_propuesta(propuesta_id):
    p = Propuesta.query.get_or_404(propuesta_id)
    if request.method == 'POST':
        p.titulo = request.form['titulo']
        p.descripcion = request.form.get('descripcion', '')
        p.horas_est = int(request.form.get('horas_est', 0))
        p.presupuesto = float(request.form.get('presupuesto', 0))
        p.estatus = request.form.get('estatus', p.estatus)
        db.session.commit()

        files = request.files.getlist('documentos')
        for f in files:
            if f and f.filename and allowed_file(f.filename):
                guardar_documento(p.id, f)

        flash('Propuesta actualizada', 'success')
        return redirect(url_for('ver_propuesta', propuesta_id=p.id))
    return render_template('propuesta_form.html', cliente=p.cliente, propuesta=p)

@app.route('/propuestas/<int:propuesta_id>/eliminar', methods=['POST'])
@login_required
def eliminar_propuesta(propuesta_id):
    p = Propuesta.query.get_or_404(propuesta_id)
    cliente_id = p.cliente_id
    # Delete files
    for doc in p.documentos:
        fp = doc.filepath
        if os.path.exists(fp):
            os.remove(fp)
    db.session.delete(p)
    db.session.commit()
    flash('Propuesta eliminada', 'success')
    return redirect(url_for('ver_cliente', cliente_id=cliente_id))

@app.route('/propuestas/<int:propuesta_id>/estatus', methods=['POST'])
@login_required
def cambiar_estatus(propuesta_id):
    p = Propuesta.query.get_or_404(propuesta_id)
    nuevo = request.form.get('estatus')
    if nuevo in ['borrador', 'enviada', 'aprobada', 'rechazada']:
        p.estatus = nuevo
        db.session.commit()
        flash(f'Estatus cambiado a "{nuevo}"', 'success')
    return redirect(url_for('ver_propuesta', propuesta_id=propuesta_id))

# ══════════════════════════════════════════════════
# ROUTES — Documentos
# ══════════════════════════════════════════════════
def allowed_file(filename):
    ext = filename.rsplit('.', 1)[-1].lower() if '.' in filename else ''
    return ext in ALLOWED_EXTENSIONS

def guardar_documento(propuesta_id, file):
    ext = file.filename.rsplit('.', 1)[-1].lower() if '.' in file.filename else ''
    filename = secure_filename(file.filename)
    ts = datetime.now().strftime('%Y%m%d_%H%M%S')
    saved_name = f"{ts}_{filename}"
    prop_dir = os.path.join(app.config['UPLOAD_FOLDER'], str(propuesta_id))
    os.makedirs(prop_dir, exist_ok=True)
    filepath = os.path.join(prop_dir, saved_name)
    file.save(filepath)
    
    doc = Documento(
        propuesta_id=propuesta_id,
        filename=filename,
        filepath=filepath,
        tipo=ext,
        descripcion=request.form.get('doc_descripcion', '') if hasattr(request, 'form') else ''
    )
    db.session.add(doc)
    db.session.commit()

@app.route('/documentos/<int:doc_id>/ver')
@login_required
def ver_documento(doc_id):
    doc = Documento.query.get_or_404(doc_id)
    if doc.tipo == 'html' and os.path.exists(doc.filepath):
        with open(doc.filepath, 'r', encoding='utf-8') as f:
            content = f.read()
        return render_template('ver_html.html', documento=doc, html_content=content)
    return send_from_directory(os.path.dirname(doc.filepath), os.path.basename(doc.filepath))

@app.route('/documentos/<int:doc_id>/descargar')
@login_required
def descargar_documento(doc_id):
    doc = Documento.query.get_or_404(doc_id)
    return send_from_directory(
        os.path.dirname(doc.filepath),
        os.path.basename(doc.filepath),
        as_attachment=True,
        download_name=doc.filename
    )

@app.route('/documentos/<int:doc_id>/eliminar', methods=['POST'])
@login_required
def eliminar_documento(doc_id):
    doc = Documento.query.get_or_404(doc_id)
    propuesta_id = doc.propuesta_id
    if os.path.exists(doc.filepath):
        os.remove(doc.filepath)
    db.session.delete(doc)
    db.session.commit()
    flash('Documento eliminado', 'success')
    return redirect(url_for('ver_propuesta', propuesta_id=propuesta_id))

# ══════════════════════════════════════════════════
# ROUTES — API (para seed y AJAX)
# ══════════════════════════════════════════════════
@app.route('/api/status')
def api_status():
    return jsonify({
        'app': 'propuestas-portal',
        'clientes': Cliente.query.count(),
        'propuestas': Propuesta.query.count(),
        'documentos': Documento.query.count()
    })

# ══════════════════════════════════════════════════
# SEED: initial data
# ══════════════════════════════════════════════════
def seed_data():
    if Cliente.query.count() > 0:
        return
    
    # Cliente 1
    c1 = Cliente(
        nombre='[Cliente MiniMaster BP+SD]',
        contacto='Por definir',
        email='',
        telefono='',
        notas='Cliente ficticio para propuesta Mini Master. 200 vendedores, 1 sociedad, 20 divisiones. SAP S/4HANA.'
    )
    db.session.add(c1)
    db.session.flush()
    
    p1 = Propuesta(
        cliente_id=c1.id,
        titulo='Mini Master Empleados → BP → SD en SAP S/4HANA',
        descripcion='Implementación de mini master de 200 empleados vendedores con sincronización a Business Partner y habilitación en SD. 200 horas, Junio 2026.',
        horas_est=200,
        presupuesto=0,
        estatus='borrador'
    )
    db.session.add(p1)
    db.session.flush()
    
    # Seed docs
    docs_dir = app.config['UPLOAD_FOLDER']
    os.makedirs(os.path.join(docs_dir, str(p1.id)), exist_ok=True)
    
    src_docs = [
        ('/home/home/Propuesta_MiniMaster_BP_SD_v1.docx', 'Propuesta_MiniMaster_BP_SD_v1.docx', 'docx', 'Propuesta técnica'),
        ('/home/home/Presentacion_MiniMaster_BP_SD_v1.pptx', 'Presentacion_MiniMaster_BP_SD_v1.pptx', 'pptx', 'Presentación ejecutiva'),
        ('/home/home/Plan_Trabajo_MiniMaster_BP_SD_v1.xlsx', 'Plan_Trabajo_MiniMaster_BP_SD_v1.xlsx', 'xlsx', 'Plan de trabajo detallado'),
    ]
    for src, fname, ftype, desc in src_docs:
        if os.path.exists(src):
            ts = datetime.now().strftime('%Y%m%d_%H%M%S')
            dest = os.path.join(docs_dir, str(p1.id), f"{ts}_{fname}")
            shutil.copy2(src, dest)
            doc = Documento(
                propuesta_id=p1.id,
                filename=fname,
                filepath=dest,
                tipo=ftype,
                descripcion=desc
            )
            db.session.add(doc)
    
    # Cliente 2 - DUNOSUSA
    c2 = Cliente(
        nombre='DUNOSUSA',
        contacto='Eduardo Moo / Isaí',
        email='',
        telefono='',
        notas='Proyecto Integración EC → ECP. H1✅ H2✅ H3🔵. E1 Diagnóstico, E2 Diseño, E3 WorkBook + Diseño Funcional.'
    )
    db.session.add(c2)
    db.session.flush()
    
    p2 = Propuesta(
        cliente_id=c2.id,
        titulo='Integración SuccessFactors EC → SAP ECP — Hito 3 Construcción',
        descripcion='Corrección de réplica PTP: FTSD, CVMAPC, colisiones IT2001, BADIs, Key Mapping. Etapa 0: Integración EC→ECP.',
        horas_est=0,
        presupuesto=0,
        estatus='borrador'
    )
    db.session.add(p2)
    
    db.session.commit()
    print("✅ Seed data inserted")

with app.app_context():
    seed_data()

# ══════════════════════════════════════════════════
# RUN
# ══════════════════════════════════════════════════
if __name__ == '__main__':
    app.run(host='0.0.0.0', port=int(os.environ.get('PORT', 9200)), debug=True)
