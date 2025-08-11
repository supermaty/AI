import hashlib
import json
import os
import re


class UserManager:
    """用户管理类，处理用户注册和登录"""

    def __init__(self, storage_file='users.json'):
        self.storage_file = storage_file
        self.users = self._load_users()

    def _load_users(self):
        """从文件加载用户数据"""
        if not os.path.exists(self.storage_file):
            return {}
        try:
            with open(self.storage_file, 'r') as f:
                return json.load(f)
        except (json.JSONDecodeError, FileNotFoundError):
            return {}

    def _save_users(self):
        """保存用户数据到文件"""
        with open(self.storage_file, 'w') as f:
            json.dump(self.users, f, indent=2)

    def _hash_password(self, password):
        """使用SHA-256加盐哈希密码"""
        salt = os.urandom(16)  # 生成随机盐
        key = hashlib.pbkdf2_hmac(
            'sha256',
            password.encode('utf-8'),
            salt,
            100000  # 迭代次数
        )
        return salt.hex() + key.hex()

    def _verify_password(self, stored_password, input_password):
        """验证密码是否匹配"""
        salt = bytes.fromhex(stored_password[:32])  # 前32字符是盐的hex
        key = bytes.fromhex(stored_password[32:])  # 剩余部分是密钥
        new_key = hashlib.pbkdf2_hmac(
            'sha256',
            input_password.encode('utf-8'),
            salt,
            100000
        )
        return new_key == key

    def _check_password_complexity(self, password):
        """检查密码复杂度"""
        errors = []
        # 1. 长度至少8位
        if len(password) < 8:
            errors.append("密码长度至少为8个字符")

        # 2. 必须包含至少一个大写字母
        if not re.search(r'[A-Z]', password):
            errors.append("密码必须包含至少一个大写字母")

        # 3. 必须包含至少一个小写字母
        if not re.search(r'[a-z]', password):
            errors.append("密码必须包含至少一个小写字母")

        # 4. 必须包含至少一个数字
        if not re.search(r'\d', password):
            errors.append("密码必须包含至少一个数字")

        # 5. 必须包含至少一个特殊字符
        if not re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
            errors.append("密码必须包含至少一个特殊字符 (!@#$%^&*(),.?\":{}|<>)")

        return errors

    def register(self, username, password):
        """注册新用户"""
        # 用户名检查
        if not username:
            return False, "用户名不能为空"
        if username in self.users:
            return False, "用户名已存在"

        # 密码复杂度检查
        complexity_errors = self._check_password_complexity(password)
        if complexity_errors:
            return False, "\n".join(complexity_errors)

        # 保存用户
        self.users[username] = self._hash_password(password)
        self._save_users()
        return True, "注册成功"

    def login(self, username, password):
        """用户登录"""
        # 用户名检查
        if not username:
            return False, "用户名不能为空"

        user_data = self.users.get(username)
        if not user_data:
            return False, "用户名不存在"

        # 密码检查
        if not password:
            return False, "密码不能为空"

        if self._verify_password(user_data, password):
            return True, "登录成功"
        return False, "密码错误"

