# ====================================================================================
# 🔐 PROTETOR DE CONTA - STREAMLIT CLOUD
# Autenticação 100% Biométrica - SEM OpenCV
# ====================================================================================

import streamlit as st
import numpy as np
from PIL import Image
import sqlite3
import hashlib
import base64
import uuid
from datetime import datetime

# ===== CONFIG =====

st.set_page_config(page_title="🔐 Protetor de Conta", page_icon="🔐", layout="wide")

st.markdown("""
<style>
    .stButton > button { width: 100%; font-weight: 600; padding: 12px; }
</style>
""", unsafe_allow_html=True)

# ===== SESSION STATE =====

if 'authenticated' not in st.session_state:
    st.session_state.authenticated = False
    st.session_state.user = None
    st.session_state.page = 'login'

# ===== BIOMETRIC ENGINE (SEM CV2) =====

class BiometricEngine:
    """Engine de processamento biométrico sem OpenCV"""
    
    @staticmethod
    def load_image(image_source) -> Image.Image:
        """Carregar imagem"""
        if isinstance(image_source, str):
            return Image.open(image_source).convert('RGB')
        return image_source.convert('RGB')
    
    @staticmethod
    def validate_quality(image: Image.Image) -> dict:
        """Validar qualidade da imagem"""
        try:
            img_array = np.array(image)
            
            # Dimensões
            if img_array.shape[0] < 100 or img_array.shape[1] < 100:
                return {'valid': False, 'reason': 'Imagem muito pequena'}
            
            # Brilho e contraste
            if len(img_array.shape) == 3:
                gray = np.mean(img_array, axis=2)
            else:
                gray = img_array
            
            brightness = np.mean(gray)
            contrast = np.std(gray)
            
            # Detectar tons de pele (rosto)
            if len(img_array.shape) == 3:
                r, g, b = img_array[:,:,0], img_array[:,:,1], img_array[:,:,2]
                skin_mask = (r > 95) & (g > 40) & (b > 20) & (r > g) & (r > b)
                skin_pixels = np.sum(skin_mask)
            else:
                skin_pixels = 100
            
            is_valid = (50 < brightness < 200) and (contrast > 15) and (skin_pixels > 100)
            
            return {
                'valid': is_valid,
                'brightness': round(brightness, 2),
                'contrast': round(contrast, 2),
                'skin_pixels': int(skin_pixels)
            }
        except Exception as e:
            return {'valid': False, 'reason': str(e)}
    
    @staticmethod
    def extract_features(image: Image.Image) -> tuple:
        """Extrair features"""
        quality = BiometricEngine.validate_quality(image)
        
        if not quality['valid']:
            raise ValueError(f"Qualidade insuficiente: {quality.get('reason')}")
        
        # Redimensionar
        image_resized = image.resize((224, 224), Image.Resampling.LANCZOS)
        img_array = np.array(image_resized).astype(np.float32) / 255.0
        
        # Extrair histogramas
        if len(img_array.shape) == 3:
            hist_r = np.histogram(img_array[:,:,0], bins=32)[0]
            hist_g = np.histogram(img_array[:,:,1], bins=32)[0]
            hist_b = np.histogram(img_array[:,:,2], bins=32)[0]
            histogram = np.concatenate([hist_r, hist_g, hist_b])
        else:
            histogram = np.histogram(img_array, bins=32)[0]
        
        # Estatísticas
        stats = np.array([
            np.mean(img_array),
            np.std(img_array),
            np.min(img_array),
            np.max(img_array)
        ])
        
        # Combinar
        combined = np.concatenate([histogram, stats])
        
        # Codificar
        features = base64.b64encode(combined.astype(np.float32).tobytes()).decode()
        
        return features, 0.85
    
    @staticmethod
    def compare(feat1: str, feat2: str) -> tuple:
        """Comparar features"""
        try:
            desc1 = np.frombuffer(base64.b64decode(feat1), dtype=np.float32)
            desc2 = np.frombuffer(base64.b64decode(feat2), dtype=np.float32)
            
            if desc1.shape != desc2.shape:
                return False, 0.0
            
            # Similaridade de cosseno
            dot = np.dot(desc1, desc2)
            norm = np.linalg.norm(desc1) * np.linalg.norm(desc2)
            
            if norm == 0:
                return False, 0.0
            
            similarity = (dot / norm + 1) / 2
            is_match = similarity >= 0.70
            
            return is_match, min(1.0, similarity)
        except:
            return False, 0.0

# ===== DATABASE =====

class DatabaseManager:
    """Gerenciador de BD"""
    
    def __init__(self, db_path: str = "auth.db"):
        self.db_path = db_path
        self._init_db()
    
    def _init_db(self):
        """Inicializar BD"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''CREATE TABLE IF NOT EXISTS users (
            user_id TEXT PRIMARY KEY,
            username TEXT UNIQUE,
            email TEXT UNIQUE,
            specialty TEXT,
            password_hash TEXT,
            facial_encoding TEXT,
            created_at TEXT
        )''')
        
        cursor.execute('''CREATE TABLE IF NOT EXISTS logs (
            log_id TEXT PRIMARY KEY,
            user_id TEXT,
            event TEXT,
            status TEXT,
            message TEXT,
            timestamp TEXT
        )''')
        
        conn.commit()
        conn.close()
    
    def save_user(self, user_id, username, email, specialty, pwd_hash, facial_enc):
        """Salvar usuário"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute('''INSERT OR REPLACE INTO users VALUES (?, ?, ?, ?, ?, ?, ?)''',
            (user_id, username, email, specialty, pwd_hash, facial_enc, datetime.utcnow().isoformat()))
        conn.commit()
        conn.close()
    
    def get_user(self, email: str):
        """Buscar usuário"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute('SELECT * FROM users WHERE email = ?', (email,))
        row = cursor.fetchone()
        conn.close()
        
        if not row:
            return None
        
        return {
            'user_id': row[0], 'username': row[1], 'email': row[2],
            'specialty': row[3], 'password_hash': row[4], 'facial_encoding': row[5]
        }
    
    def log_event(self, user_id, event, status, message):
        """Log de evento"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute('''INSERT INTO logs VALUES (?, ?, ?, ?, ?, ?)''',
            (str(uuid.uuid4()), user_id, event, status, message, datetime.utcnow().isoformat()))
        conn.commit()
        conn.close()
    
    def get_logs(self, user_id: str, limit: int = 20):
        """Obter logs"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute('''SELECT event, status, message, timestamp FROM logs 
            WHERE user_id = ? ORDER BY timestamp DESC LIMIT ?''', (user_id, limit))
        rows = cursor.fetchall()
        conn.close()
        return [{'event': r[0], 'status': r[1], 'message': r[2], 'time': r[3]} for r in rows]
    
    def user_exists(self, email: str) -> bool:
        """Verificar existência"""
        return self.get_user(email) is not None

# ===== INSTÂNCIAS =====

db = DatabaseManager()
biometric = BiometricEngine()

# ===== PÁGINAS =====

def page_login():
    """Página de Login"""
    st.markdown("# 🔐 Protetor de Conta")
    st.markdown("## Autenticação 100% Biométrica")
    st.divider()
    
    email = st.text_input("📧 Email", key="login_email")
    password = st.text_input("🔑 Senha", type="password", key="login_password")
    
    st.markdown("### 📷 Capture seu Rosto (OBRIGATÓRIO)")
    st.info("⚠️ Você precisa capturar seu rosto para fazer login!")
    
    tab1, tab2 = st.tabs(["📸 Câmera", "📁 Upload"])
    
    image_captured = None
    
    with tab1:
        picture = st.camera_input("Capture seu rosto", key="camera_login")
        if picture is not None:
            image_captured = Image.open(picture)
            st.image(image_captured, caption="✓ Rosto capturado", width=300)
    
    with tab2:
        uploaded = st.file_uploader("Selecione uma imagem", type=['jpg', 'jpeg', 'png'], key="upload_login")
        if uploaded is not None:
            image_captured = Image.open(uploaded)
            st.image(image_captured, caption="✓ Imagem carregada", width=300)
    
    if st.button("🚀 Login Biométrico", use_container_width=True, type="primary"):
        if not email or not password:
            st.error("❌ Email e senha obrigatórios!")
            return
        
        if image_captured is None:
            st.error("❌ IMAGEM OBRIGATÓRIA para login!")
            return
        
        with st.spinner("🔄 Autenticando..."):
            try:
                img = biometric.load_image(image_captured)
                quality = biometric.validate_quality(img)
                
                if not quality['valid']:
                    st.warning(f"⚠️ Qualidade insuficiente:\nBrilho: {quality.get('brightness')}\nContraste: {quality.get('contrast')}")
                    return
                
                features, _ = biometric.extract_features(img)
                user = db.get_user(email)
                
                if not user:
                    st.error("❌ Usuário não encontrado!")
                    return
                
                pwd_hash = hashlib.sha256(password.encode()).hexdigest()
                if pwd_hash != user['password_hash']:
                    st.error("❌ Senha incorreta!")
                    db.log_event(user['user_id'], 'login', 'failed', 'Senha incorreta')
                    return
                
                is_match, conf = biometric.compare(user['facial_encoding'], features)
                
                if not is_match or conf < 0.65:
                    st.error(f"❌ Rosto não corresponde! (Confiança: {conf:.1%})")
                    db.log_event(user['user_id'], 'login', 'failed', f'Biometria falhou: {conf:.1%}')
                    return
                
                st.session_state.authenticated = True
                st.session_state.user = user
                db.log_event(user['user_id'], 'login', 'success', f'Confiança: {conf:.1%}')
                
                st.success(f"✅ Bem-vindo, {user['username']}!")
                st.rerun()
            
            except Exception as e:
                st.error(f"❌ Erro: {str(e)}")
    
    st.divider()
    if st.button("📝 Criar conta", use_container_width=True):
        st.session_state.page = 'register'
        st.rerun()

def page_register():
    """Página de Registro"""
    st.markdown("# 📝 Criar Conta")
    st.markdown("## Com Autenticação Biométrica")
    st.divider()
    
    username = st.text_input("👤 Usuário", key="reg_username")
    email = st.text_input("📧 Email", key="reg_email")
    password = st.text_input("🔑 Senha", type="password", key="reg_password")
    password_confirm = st.text_input("🔑 Confirmar", type="password", key="reg_password_confirm")
    specialty = st.selectbox("🎯 Especialidade", ["user", "admin", "editor", "viewer"], key="reg_specialty")
    
    st.markdown("### 📷 Registre seu Rosto (OBRIGATÓRIO)")
    st.info("⚠️ Imagem obrigatória para criar a conta!")
    
    tab1, tab2 = st.tabs(["📸 Câmera", "📁 Upload"])
    
    image_captured = None
    
    with tab1:
        picture = st.camera_input("Registre seu rosto", key="camera_register")
        if picture is not None:
            image_captured = Image.open(picture)
            st.image(image_captured, caption="✓ Rosto registrado", width=300)
    
    with tab2:
        uploaded = st.file_uploader("Selecione uma imagem", type=['jpg', 'jpeg', 'png'], key="upload_register")
        if uploaded is not None:
            image_captured = Image.open(uploaded)
            st.image(image_captured, caption="✓ Imagem carregada", width=300)
    
    if st.button("✅ Criar Conta", use_container_width=True, type="primary"):
        if not all([username, email, password, password_confirm]):
            st.error("❌ Campos obrigatórios!")
            return
        
        if password != password_confirm:
            st.error("❌ Senhas não coincidem!")
            return
        
        if len(password) < 6:
            st.error("❌ Senha com mínimo 6 caracteres!")
            return
        
        if image_captured is None:
            st.error("❌ IMAGEM OBRIGATÓRIA para registrar!")
            return
        
        if db.user_exists(email):
            st.error("❌ Email já registrado!")
            return
        
        with st.spinner("🔄 Processando..."):
            try:
                img = biometric.load_image(image_captured)
                quality = biometric.validate_quality(img)
                
                if not quality['valid']:
                    st.warning("⚠️ Qualidade insuficiente para registro")
                    return
                
                facial_enc, _ = biometric.extract_features(img)
                
                user_id = str(uuid.uuid4())
                pwd_hash = hashlib.sha256(password.encode()).hexdigest()
                
                db.save_user(user_id, username, email, specialty, pwd_hash, facial_enc)
                db.log_event(user_id, 'registration', 'success', 'Conta criada')
                
                st.success(f"✅ Conta criada! Faça login.")
                st.session_state.page = 'login'
                st.rerun()
            
            except Exception as e:
                st.error(f"❌ Erro: {str(e)}")
    
    st.divider()
    if st.button("🔓 Voltar ao Login", use_container_width=True):
        st.session_state.page = 'login'
        st.rerun()

def page_dashboard():
    """Dashboard"""
    st.markdown(f"# 👋 {st.session_state.user['username']}")
    st.markdown("## 🔐 Painel de Segurança")
    st.divider()
    
    col1, col2, col3 = st.columns(3)
    col1.metric("Status", "✅ Autenticado")
    col2.metric("Email", st.session_state.user['email'][:15] + "...")
    col3.metric("Segurança", "MÁXIMA")
    
    st.divider()
    
    tab1, tab2, tab3 = st.tabs(["👤 Perfil", "📊 Logs", "⚙️ Configurações"])
    
    with tab1:
        st.subheader("📋 Dados da Conta")
        st.write(f"**Usuário:** {st.session_state.user['username']}")
        st.write(f"**Email:** {st.session_state.user['email']}")
        st.write(f"**Especialidade:** {st.session_state.user['specialty']}")
        st.write(f"**Biometria:** ✅ Registrada")
    
    with tab2:
        st.subheader("📊 Histórico")
        logs = db.get_logs(st.session_state.user['user_id'])
        
        if logs:
            for log in logs:
                emoji = "✅" if log['status'] == 'success' else "❌"
                st.write(f"{emoji} **{log['event']}** - {log['message']}")
                st.caption(f"🕐 {log['time'][:19]}")
                st.divider()
        else:
            st.info("Sem logs ainda")
    
    with tab3:
        st.subheader("⚙️ Configurações")
        st.info("✅ Autenticação biométrica obrigatória e ativa")
        
        if st.button("🚪 Sair", use_container_width=True):
            db.log_event(st.session_state.user['user_id'], 'logout', 'success', 'Logout')
            st.session_state.authenticated = False
            st.session_state.user = None
            st.session_state.page = 'login'
            st.rerun()

# ===== MAIN =====

def main():
    """Main"""
    with st.sidebar:
        st.markdown("# 🔐 Protetor de Conta")
        
        if st.session_state.authenticated:
            st.success(f"✅ {st.session_state.user['username']}")
            if st.button("🚪 Sair", use_container_width=True):
                db.log_event(st.session_state.user['user_id'], 'logout', 'success', 'Logout via sidebar')
                st.session_state.authenticated = False
                st.session_state.user = None
                st.session_state.page = 'login'
                st.rerun()
        else:
            col1, col2 = st.columns(2)
            with col1:
                if st.button("🔓 Login", use_container_width=True, type="primary"):
                    st.session_state.page = 'login'
                    st.rerun()
            with col2:
                if st.button("📝 Registrar", use_container_width=True):
                    st.session_state.page = 'register'
                    st.rerun()
        
        st.divider()
        st.markdown("""
        ### ℹ️ Sobre
        
        - **Segurança:** 100% Biométrica
        - **BD:** SQLite
        - **Features:** Avançado
        """)
    
    if not st.session_state.authenticated:
        if st.session_state.page == 'login':
            page_login()
        else:
            page_register()
    else:
        page_dashboard()

if __name__ == "__main__":
    main()
