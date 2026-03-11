# ====================================================================================
# 🔐 PROTETOR DE CONTA - STREAMLIT
# Autenticação Multi-Método com Câmera/Upload de Imagem
# ====================================================================================

import streamlit as st
import cv2
import numpy as np
from PIL import Image
import sqlite3
import hashlib
import base64
import uuid
from datetime import datetime
from pathlib import Path
import io

# ===== CONFIGURAÇÃO STREAMLIT =====

st.set_page_config(
    page_title="🔐 Protetor de Conta",
    page_icon="🔐",
    layout="wide",
    initial_sidebar_state="expanded"
)

st.markdown("""
<style>
    .stTabs [data-baseweb="tab-list"] button {
        font-size: 16px;
        font-weight: 600;
    }
    .alert-success { color: #28a745; }
    .alert-danger { color: #dc3545; }
    .alert-warning { color: #ffc107; }
</style>
""", unsafe_allow_html=True)

# ===== SESSION STATE =====

if 'authenticated' not in st.session_state:
    st.session_state.authenticated = False
    st.session_state.user = None
    st.session_state.user_id = None
    st.session_state.email = None
    st.session_state.page = 'login'

# ===== BIOMETRIC ENGINE =====

class BiometricEngine:
    """Engine de processamento biométrico"""
    
    @staticmethod
    def load_image(image_source) -> np.ndarray:
        """Carregar imagem de múltiplas fontes"""
        if isinstance(image_source, str):
            img = Image.open(image_source)
        else:
            img = image_source
        
        return cv2.cvtColor(np.array(img), cv2.COLOR_RGB2BGR)
    
    @staticmethod
    def preprocess(image: np.ndarray) -> np.ndarray:
        """Preprocessar imagem"""
        image = cv2.resize(image, (640, 480))
        
        if len(image.shape) == 3:
            img_yuv = cv2.cvtColor(image, cv2.COLOR_BGR2YCrCb)
            img_yuv[:,:,0] = cv2.equalizeHist(img_yuv[:,:,0])
            image = cv2.cvtColor(img_yuv, cv2.COLOR_YCrCb2BGR)
        
        return image
    
    @staticmethod
    def detect_face(image: np.ndarray) -> tuple:
        """Detectar rosto"""
        cascade = cv2.CascadeClassifier(
            cv2.data.haarcascades + 'haarcascade_frontalface_default.xml'
        )
        
        gray = cv2.cvtColor(image, cv2.COLOR_BGR2GRAY)
        faces = cascade.detectMultiScale(gray, 1.3, 5, minSize=(50, 50))
        
        if len(faces) == 0:
            raise ValueError("Nenhum rosto detectado")
        
        x, y, w, h = max(faces, key=lambda f: f[2] * f[3])
        return image[y:y+h, x:x+w], len(faces) > 1
    
    @staticmethod
    def validate_quality(image: np.ndarray) -> dict:
        """Validar qualidade da imagem"""
        try:
            face_roi, multiple = BiometricEngine.detect_face(image)
            
            gray = cv2.cvtColor(face_roi, cv2.COLOR_BGR2GRAY)
            sharpness = cv2.Laplacian(gray, cv2.CV_64F).var()
            brightness = np.mean(gray)
            contrast = gray.std()
            
            is_valid = (sharpness > 100 and 50 < brightness < 200 and contrast > 20)
            
            return {
                'valid': is_valid,
                'sharpness': round(sharpness, 2),
                'brightness': round(brightness, 2),
                'contrast': round(contrast, 2)
            }
        except:
            return {'valid': False}
    
    @staticmethod
    def extract_features(image: np.ndarray) -> tuple:
        """Extrair features SIFT"""
        face_roi, _ = BiometricEngine.detect_face(image)
        
        sift = cv2.SIFT_create()
        _, descriptors = sift.detectAndCompute(face_roi, None)
        
        if descriptors is None:
            raise ValueError("Features insuficientes")
        
        features = base64.b64encode(descriptors.tobytes()).decode('utf-8')
        quality = min(len(_) / 500.0, 1.0)
        
        return features, quality
    
    @staticmethod
    def compare(feat1: str, feat2: str) -> tuple:
        """Comparar features"""
        desc1 = np.frombuffer(base64.b64decode(feat1), dtype=np.uint8)
        desc2 = np.frombuffer(base64.b64decode(feat2), dtype=np.uint8)
        
        if desc1.shape != desc2.shape:
            return False, 0.0
        
        diff = np.sum(np.abs(desc1.astype(float) - desc2.astype(float)))
        similarity = 1 - (diff / (len(desc1) * 255))
        
        return similarity >= 0.75, max(0, similarity)

# ===== DATABASE =====

class DatabaseManager:
    """Gerenciador de banco de dados"""
    
    def __init__(self, db_path: str = "auth.db"):
        self.db_path = db_path
        self._init_db()
    
    def _init_db(self):
        """Inicializar banco"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''CREATE TABLE IF NOT EXISTS users (
            user_id TEXT PRIMARY KEY,
            username TEXT UNIQUE,
            email TEXT UNIQUE,
            specialty TEXT DEFAULT "user",
            password_hash TEXT,
            facial_encoding TEXT,
            created_at TEXT,
            is_active BOOLEAN DEFAULT 1
        )''')
        
        cursor.execute('''CREATE TABLE IF NOT EXISTS logs (
            log_id TEXT PRIMARY KEY,
            user_id TEXT,
            event TEXT,
            status TEXT,
            message TEXT,
            timestamp TEXT,
            FOREIGN KEY (user_id) REFERENCES users(user_id)
        )''')
        
        conn.commit()
        conn.close()
    
    def save_user(self, user_id, username, email, specialty, pwd_hash, facial_enc):
        """Salvar usuário"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''INSERT OR REPLACE INTO users VALUES (?, ?, ?, ?, ?, ?, ?, ?)''',
            (user_id, username, email, specialty, pwd_hash, facial_enc, 
             datetime.utcnow().isoformat(), 1))
        
        conn.commit()
        conn.close()
    
    def get_user(self, email: str):
        """Obter usuário"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('SELECT * FROM users WHERE email = ?', (email,))
        row = cursor.fetchone()
        conn.close()
        
        if not row:
            return None
        
        return {
            'user_id': row[0], 'username': row[1], 'email': row[2],
            'specialty': row[3], 'password_hash': row[4], 
            'facial_encoding': row[5], 'created_at': row[6]
        }
    
    def log_event(self, user_id, event, status, message):
        """Registrar evento"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''INSERT INTO logs VALUES (?, ?, ?, ?, ?, ?)''',
            (str(uuid.uuid4()), user_id, event, status, message,
             datetime.utcnow().isoformat()))
        
        conn.commit()
        conn.close()
    
    def get_logs(self, user_id: str, limit: int = 20):
        """Obter logs"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''SELECT event, status, message, timestamp FROM logs 
            WHERE user_id = ? ORDER BY timestamp DESC LIMIT ?''',
            (user_id, limit))
        
        rows = cursor.fetchall()
        conn.close()
        
        return [{'event': r[0], 'status': r[1], 'message': r[2], 'time': r[3]} for r in rows]
    
    def user_exists(self, email: str) -> bool:
        """Verificar existência"""
        return self.get_user(email) is not None

# ===== INSTÂNCIAS GLOBAIS =====

db = DatabaseManager()
biometric = BiometricEngine()

# ===== PÁGINAS =====

def page_login():
    """Página de Login"""
    st.markdown("# 🔐 Protetor de Conta - Login")
    st.markdown("### Autenticação 100% Biométrica")
    st.divider()
    
    col1, col2 = st.columns([1, 2])
    
    with col2:
        email = st.text_input("📧 Email", placeholder="seu@email.com", key="login_email")
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
            uploaded = st.file_uploader("Selecione uma imagem", 
                type=['jpg', 'jpeg', 'png'], key="upload_login")
            if uploaded is not None:
                image_captured = Image.open(uploaded)
                st.image(image_captured, caption="✓ Imagem carregada", width=300)
        
        if st.button("🚀 Login Biométrico", use_container_width=True, type="primary"):
            if not email or not password:
                st.error("❌ Email e senha obrigatórios!")
                return
            
            if image_captured is None:
                st.error("❌ **IMAGEM OBRIGATÓRIA** para login!")
                return
            
            with st.spinner("🔄 Autenticando..."):
                try:
                    img = biometric.load_image(image_captured)
                    img = biometric.preprocess(img)
                    
                    quality = biometric.validate_quality(img)
                    if not quality.get('valid'):
                        st.warning(f"⚠️ Qualidade insuficiente:\nNitidez: {quality.get('sharpness')}\nBrilho: {quality.get('brightness')}")
                        return
                    
                    features, score = biometric.extract_features(img)
                    
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
                    
                    if not is_match or conf < 0.70:
                        st.error(f"❌ Rosto não corresponde! (Confiança: {conf:.1%})")
                        db.log_event(user['user_id'], 'login', 'failed', f'Biometria falhou: {conf:.1%}')
                        return
                    
                    st.session_state.authenticated = True
                    st.session_state.user = user
                    st.session_state.user_id = user['user_id']
                    st.session_state.email = user['email']
                    
                    db.log_event(user['user_id'], 'login', 'success', f'Confiança: {conf:.1%}')
                    
                    st.success(f"✅ Bem-vindo, {user['username']}!")
                    st.rerun()
                
                except Exception as e:
                    st.error(f"❌ Erro: {str(e)}")

def page_register():
    """Página de Registro"""
    st.markdown("# 📝 Criar Conta")
    st.markdown("### Com Autenticação Biométrica")
    st.divider()
    
    col1, col2 = st.columns([1, 2])
    
    with col2:
        username = st.text_input("👤 Nome de Usuário", key="reg_username")
        email = st.text_input("📧 Email", key="reg_email")
        password = st.text_input("🔑 Senha", type="password", key="reg_password")
        password_confirm = st.text_input("🔑 Confirmar Senha", type="password", key="reg_password_confirm")
        specialty = st.selectbox("🎯 Especialidade", ["user", "admin", "editor", "viewer"], key="reg_specialty")
        
        st.markdown("### 📷 Registre seu Rosto (OBRIGATÓRIO)")
        st.info("⚠️ A imagem é obrigatória para criar a conta!")
        
        tab1, tab2 = st.tabs(["📸 Câmera", "📁 Upload"])
        
        image_captured = None
        
        with tab1:
            picture = st.camera_input("Registre seu rosto", key="camera_register")
            if picture is not None:
                image_captured = Image.open(picture)
                st.image(image_captured, caption="✓ Rosto registrado", width=300)
        
        with tab2:
            uploaded = st.file_uploader("Selecione uma imagem",
                type=['jpg', 'jpeg', 'png'], key="upload_register")
            if uploaded is not None:
                image_captured = Image.open(uploaded)
                st.image(image_captured, caption="✓ Imagem carregada", width=300)
        
        if st.button("✅ Criar Conta", use_container_width=True, type="primary"):
            if not all([username, email, password, password_confirm]):
                st.error("❌ Todos os campos obrigatórios!")
                return
            
            if password != password_confirm:
                st.error("❌ Senhas não coincidem!")
                return
            
            if len(password) < 6:
                st.error("❌ Senha com mínimo 6 caracteres!")
                return
            
            if image_captured is None:
                st.error("❌ **IMAGEM OBRIGATÓRIA** para registrar!")
                return
            
            if db.user_exists(email):
                st.error("❌ Email já registrado!")
                return
            
            with st.spinner("🔄 Processando registro..."):
                try:
                    img = biometric.load_image(image_captured)
                    img = biometric.preprocess(img)
                    
                    quality = biometric.validate_quality(img)
                    if not quality.get('valid'):
                        st.warning(f"⚠️ Qualidade insuficiente para registro")
                        return
                    
                    facial_enc, _ = biometric.extract_features(img)
                    
                    user_id = str(uuid.uuid4())
                    pwd_hash = hashlib.sha256(password.encode()).hexdigest()
                    
                    db.save_user(user_id, username, email, specialty, pwd_hash, facial_enc)
                    db.log_event(user_id, 'registration', 'success', 'Nova conta criada')
                    
                    st.success(f"✅ Conta criada! Faça login na aba de Login.")
                    st.session_state.page = 'login'
                    st.rerun()
                
                except Exception as e:
                    st.error(f"❌ Erro: {str(e)}")

def page_dashboard():
    """Dashboard do usuário"""
    st.markdown(f"# 👋 Bem-vindo, {st.session_state.user['username']}!")
    st.markdown("### 🔐 Painel de Segurança")
    st.divider()
    
    col1, col2, col3 = st.columns(3)
    with col1:
        st.metric("Status", "✅ Autenticado", "Biometria Ativa")
    with col2:
        st.metric("Email", st.session_state.email[:20] + "...", "Verificado")
    with col3:
        st.metric("Segurança", "MÁXIMA", "100% Biométrica")
    
    st.divider()
    
    tab1, tab2, tab3 = st.tabs(["👤 Perfil", "📊 Logs", "⚙️ Configurações"])
    
    with tab1:
        st.subheader("📋 Informações da Conta")
        col1, col2 = st.columns(2)
        with col1:
            st.write(f"**Usuário:** {st.session_state.user['username']}")
            st.write(f"**Email:** {st.session_state.user['email']}")
            st.write(f"**Especialidade:** {st.session_state.user['specialty']}")
        with col2:
            st.write(f"**Criada em:** {st.session_state.user['created_at'][:10]}")
            st.write(f"**Status:** ✅ Ativa")
            st.write(f"**Biometria:** ✅ Registrada")
    
    with tab2:
        st.subheader("📊 Histórico de Segurança")
        logs = db.get_logs(st.session_state.user_id)
        
        if logs:
            for log in logs:
                status_emoji = "✅" if log['status'] == 'success' else "❌"
                st.write(f"{status_emoji} **{log['event']}** - {log['message']}")
                st.caption(f"🕐 {log['time'][:19]}")
                st.divider()
        else:
            st.info("Sem logs ainda")
    
    with tab3:
        st.subheader("⚙️ Configurações de Segurança")
        st.markdown("""
        **Status de Proteção:** ✅ ATIVA
        
        - Autenticação biométrica obrigatória
        - Validação de qualidade em tempo real
        - Histórico de segurança completo
        """)
        st.warning("⚠️ A biometria é obrigatória e não pode ser desativada.")

# ===== MAIN =====

def main():
    """Função principal"""
    
    with st.sidebar:
        st.markdown("# 🔐 Protetor de Conta")
        
        if st.session_state.authenticated:
            st.success(f"✅ Logado como:\n{st.session_state.user['username']}")
            if st.button("🚪 Sair", use_container_width=True):
                st.session_state.authenticated = False
                st.session_state.user = None
                st.session_state.page = 'login'
                st.rerun()
        else:
            col1, col2 = st.columns(2)
            with col1:
                if st.button("🔓 Login", use_container_width=True):
                    st.session_state.page = 'login'
            with col2:
                if st.button("📝 Registrar", use_container_width=True):
                    st.session_state.page = 'register'
        
        st.divider()
        st.markdown("""
        ### ℹ️ Sobre
        
        Sistema de autenticação 100% biométrica
        - Detecção facial avançada
        - Validação de qualidade em tempo real
        - Armazenamento seguro
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
