import unittest
from unittest.mock import patch, mock_open
from user_manager import UserManager

# 单元测试
class TestUserManager(unittest.TestCase):
    def setUp(self):
        self.manager = UserManager()
        # 模拟空用户数据库
        self.manager.users = {}
        self.test_user = "test_user"
        self.test_password = "Secure@123"  # 符合所有复杂度要求

    def test_successful_registration(self):
        """测试成功注册"""
        success, msg = self.manager.register(self.test_user, self.test_password)
        self.assertTrue(success)
        self.assertIn(self.test_user, self.manager.users)

    def test_duplicate_registration(self):
        """测试重复注册"""
        self.manager.register(self.test_user, self.test_password)
        success, msg = self.manager.register(self.test_user, "NewPassword@456")
        self.assertFalse(success)
        self.assertEqual(msg, "用户名已存在")

    def test_empty_username(self):
        """测试空用户名"""
        success, msg = self.manager.register("", self.test_password)
        self.assertFalse(success)
        self.assertEqual(msg, "用户名不能为空")

        success, msg = self.manager.login("", "any")
        self.assertFalse(success)
        self.assertEqual(msg, "用户名不能为空")

    def test_empty_password(self):
        """测试空密码"""
        success, msg = self.manager.register(self.test_user, "")
        self.assertFalse(success)
        self.assertIn("密码长度至少为8个字符", msg)

        self.manager.register(self.test_user, self.test_password)
        success, msg = self.manager.login(self.test_user, "")
        self.assertFalse(success)
        self.assertEqual(msg, "密码不能为空")

    def test_password_complexity_checks(self):
        """测试密码复杂度规则"""
        # 长度不足
        success, msg = self.manager.register("user1", "Short1!")
        self.assertFalse(success)
        self.assertIn("密码长度至少为8个字符", msg)

        # 缺少大写字母
        success, msg = self.manager.register("user2", "lowercase123!")
        self.assertFalse(success)
        self.assertIn("密码必须包含至少一个大写字母", msg)

        # 缺少小写字母
        success, msg = self.manager.register("user3", "UPPERCASE123!")
        self.assertFalse(success)
        self.assertIn("密码必须包含至少一个小写字母", msg)

        # 缺少数字
        success, msg = self.manager.register("user4", "NoNumberHere!")
        self.assertFalse(success)
        self.assertIn("密码必须包含至少一个数字", msg)

        # 缺少特殊字符
        success, msg = self.manager.register("user5", "MissingSpecial123")
        self.assertFalse(success)
        self.assertIn("密码必须包含至少一个特殊字符", msg)

        # 所有条件满足
        success, msg = self.manager.register("user6", "Valid@Pass123")
        self.assertTrue(success)

    def test_successful_login(self):
        """测试成功登录"""
        self.manager.register(self.test_user, self.test_password)
        success, msg = self.manager.login(self.test_user, self.test_password)
        self.assertTrue(success)

    def test_wrong_password(self):
        """测试错误密码"""
        self.manager.register(self.test_user, self.test_password)
        success, msg = self.manager.login(self.test_user, "Wrong@Password123")
        self.assertFalse(success)
        self.assertEqual(msg, "密码错误")

    def test_invalid_username(self):
        """测试无效用户名"""
        success, msg = self.manager.login("non_existent_user", "anyPassword")
        self.assertFalse(success)
        self.assertEqual(msg, "用户名不存在")

    def test_password_hashing(self):
        """测试密码哈希和验证"""
        hashed = self.manager._hash_password(self.test_password)
        # 验证相同密码
        self.assertTrue(self.manager._verify_password(hashed, self.test_password))
        # 验证不同密码
        self.assertFalse(self.manager._verify_password(hashed, "Different@123"))

        # 测试相同密码不同哈希（盐值不同）
        hashed2 = self.manager._hash_password(self.test_password)
        self.assertNotEqual(hashed, hashed2)

    @patch("builtins.open", mock_open(read_data='{"user1": "salt123hash123"}'))
    def test_load_users(self):
        """测试用户数据加载"""
        manager = UserManager()
        self.assertEqual(manager.users, {"user1": "salt123hash123"})

    @patch("builtins.open", mock_open(read_data='invalid json'))
    def test_corrupted_data(self):
        """测试损坏的数据文件"""
        manager = UserManager()
        self.assertEqual(manager.users, {})


if __name__ == "__main__":
    unittest.main()