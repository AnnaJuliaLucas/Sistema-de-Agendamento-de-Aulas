"""
Módulo de Utilitários de Segurança
Implementa criptografia adequada para senhas e comunicação segura
"""

import bcrypt
import hashlib
import secrets
import base64
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.fernet import Fernet
import jwt
from datetime import datetime, timedelta
import json

class SecurityManager:
    """Gerenciador de segurança para o sistema de agendamento"""
    
    def __init__(self):
        self.private_key = None
        self.public_key = None
        self.fernet_key = None
        self.jwt_secret = secrets.token_urlsafe(32)
        self._generate_rsa_keys()
    
    def _generate_rsa_keys(self):
        """Gera par de chaves RSA para criptografia híbrida"""
        self.private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048
        )
        self.public_key = self.private_key.public_key()
    
    def get_public_key_pem(self):
        """Retorna a chave pública em formato PEM"""
        return self.public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
    
    def hash_password_client_side(self, password: str, salt: str = None) -> dict:
        """
        Hash da senha no lado cliente antes da transmissão
        Retorna salt e hash para envio seguro ao servidor
        """
        if salt is None:
            salt = secrets.token_hex(16)
        
        # Primeiro hash com salt personalizado (cliente)
        client_hash = hashlib.pbkdf2_hmac(
            'sha256',
            password.encode('utf-8'),
            salt.encode('utf-8'),
            100000  # 100k iterações
        )
        
        return {
            'salt': salt,
            'client_hash': base64.b64encode(client_hash).decode('utf-8')
        }
    
    def hash_password_server_side(self, client_hash: str) -> str:
        """
        Hash adicional no servidor usando bcrypt
        Dupla proteção: cliente + servidor
        """
        # Segundo hash no servidor com bcrypt
        server_hash = bcrypt.hashpw(
            client_hash.encode('utf-8'),
            bcrypt.gensalt(rounds=12)
        )
        return server_hash.decode('utf-8')
    
    def verify_password_server_side(self, client_hash: str, stored_hash: str) -> bool:
        """Verifica hash do cliente contra hash armazenado no servidor"""
        return bcrypt.checkpw(
            client_hash.encode('utf-8'),
            stored_hash.encode('utf-8')
        )
    
    def verify_password(self, password: str, salt: str, stored_hash: str) -> bool:
        """Verifica senha comparando hashes"""
        # Recria o hash do cliente
        client_data = self.hash_password_client_side(password, salt)
        client_hash = client_data['client_hash']
        
        # Verifica com bcrypt no servidor
        return bcrypt.checkpw(
            client_hash.encode('utf-8'),
            stored_hash.encode('utf-8')
        )
    
    def generate_fernet_key(self) -> bytes:
        """Gera chave simétrica Fernet para criptografia de dados"""
        self.fernet_key = Fernet.generate_key()
        return self.fernet_key
    
    def encrypt_with_rsa(self, data: bytes, public_key_pem: bytes) -> bytes:
        """Criptografa dados com RSA (para chaves pequenas)"""
        public_key = serialization.load_pem_public_key(public_key_pem)
        encrypted = public_key.encrypt(
            data,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        return encrypted
    
    def decrypt_with_rsa(self, encrypted_data: bytes) -> bytes:
        """Descriptografa dados com RSA"""
        decrypted = self.private_key.decrypt(
            encrypted_data,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        return decrypted
    
    def encrypt_message(self, message: str) -> dict:
        """
        Criptografia híbrida: RSA para chave + Fernet para dados
        """
        if not self.fernet_key:
            self.generate_fernet_key()
        
        # Criptografa mensagem com Fernet
        fernet = Fernet(self.fernet_key)
        encrypted_message = fernet.encrypt(message.encode('utf-8'))
        
        return {
            'encrypted_data': base64.b64encode(encrypted_message).decode('utf-8'),
            'fernet_key': base64.b64encode(self.fernet_key).decode('utf-8')
        }
    
    def decrypt_message(self, encrypted_data: str, fernet_key: str) -> str:
        """Descriptografa mensagem usando Fernet"""
        fernet = Fernet(base64.b64decode(fernet_key.encode('utf-8')))
        decrypted = fernet.decrypt(base64.b64decode(encrypted_data.encode('utf-8')))
        return decrypted.decode('utf-8')
    
    def generate_jwt_token(self, user_id: str, user_type: str, expires_hours: int = 24) -> str:
        """Gera token JWT para autenticação"""
        payload = {
            'user_id': user_id,
            'user_type': user_type,
            'exp': datetime.utcnow() + timedelta(hours=expires_hours),
            'iat': datetime.utcnow()
        }
        return jwt.encode(payload, self.jwt_secret, algorithm='HS256')
    
    def verify_jwt_token(self, token: str) -> dict:
        """Verifica e decodifica token JWT"""
        try:
            payload = jwt.decode(token, self.jwt_secret, algorithms=['HS256'])
            return {'valid': True, 'payload': payload}
        except jwt.ExpiredSignatureError:
            return {'valid': False, 'error': 'Token expirado'}
        except jwt.InvalidTokenError:
            return {'valid': False, 'error': 'Token inválido'}
    
    def secure_login_flow(self, username: str, password: str, stored_data: dict) -> dict:
        """
        Fluxo completo de login seguro
        stored_data deve conter: {'salt': str, 'hash': str}
        """
        if not stored_data:
            return {'success': False, 'error': 'Usuário não encontrado'}
        
        # Verifica senha
        if self.verify_password(password, stored_data['salt'], stored_data['hash']):
            # Gera token JWT
            token = self.generate_jwt_token(username, 'user')
            return {
                'success': True,
                'token': token,
                'message': 'Login realizado com sucesso'
            }
        else:
            return {'success': False, 'error': 'Senha incorreta'}

# Exemplo de uso
if __name__ == "__main__":
    # Demonstração do uso seguro
    security = SecurityManager()
    
    # Simulação de cadastro
    print("=== CADASTRO SEGURO ===")
    password = "minhaSenhaSegura123!"
    
    # Hash no cliente
    client_data = security.hash_password_client_side(password)
    print(f"Salt: {client_data['salt']}")
    print(f"Hash do cliente: {client_data['client_hash'][:20]}...")
    
    # Hash no servidor
    server_hash = security.hash_password_server_side(client_data['client_hash'])
    print(f"Hash do servidor: {server_hash[:20]}...")
    
    # Dados para armazenar no banco
    stored_data = {
        'salt': client_data['salt'],
        'hash': server_hash
    }
    
    # Simulação de login
    print("\n=== LOGIN SEGURO ===")
    login_result = security.secure_login_flow("usuario_teste", password, stored_data)
    print(f"Resultado: {login_result}")
    
    # Teste de criptografia de mensagem
    print("\n=== CRIPTOGRAFIA DE MENSAGEM ===")
    message = "Dados sensíveis do usuário"
    encrypted = security.encrypt_message(message)
    print(f"Mensagem criptografada: {encrypted['encrypted_data'][:20]}...")
    
    decrypted = security.decrypt_message(encrypted['encrypted_data'], encrypted['fernet_key'])
    print(f"Mensagem descriptografada: {decrypted}")

