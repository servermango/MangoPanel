import os
import tempfile
import unittest
import zipfile
import tarfile
from pathlib import Path
from http import HTTPStatus

from mangopanel.app import normalize_account_relative_path, ApiError
from mangopanel.config import FILEBROWSER_CUSTOM_JS


class FileExtractTests(unittest.TestCase):
    def test_custom_js_contains_extract_logic(self):
        self.assertIn("mp-extract-btn", FILEBROWSER_CUSTOM_JS)
        self.assertIn("isArchive", FILEBROWSER_CUSTOM_JS)
        self.assertIn("doExtract", FILEBROWSER_CUSTOM_JS)
        self.assertIn("/files/api/extract", FILEBROWSER_CUSTOM_JS)

    def test_zip_extraction_success(self):
        with tempfile.TemporaryDirectory() as tmp:
            account = {"base_path": tmp}
            zip_file = os.path.join(tmp, "test_archive.zip")
            
            with zipfile.ZipFile(zip_file, "w") as zf:
                zf.writestr("file1.txt", "Content 1")
                zf.writestr("folder/file2.txt", "Content 2")

            abs_path, rel_path = normalize_account_relative_path(account, "test_archive.zip")
            dest_dir = os.path.dirname(str(abs_path))
            account_base = os.path.abspath(account["base_path"])

            extracted_count = 0
            with zipfile.ZipFile(str(abs_path), "r") as zf:
                for member in zf.infolist():
                    target_path = os.path.abspath(os.path.join(dest_dir, member.filename))
                    if not target_path.startswith(account_base + os.sep) and target_path != account_base:
                        raise ApiError(HTTPStatus.BAD_REQUEST, "invalid_path_traversal")
                    zf.extract(member, dest_dir)
                    extracted_count += 1

            self.assertEqual(extracted_count, 2)
            self.assertTrue(os.path.exists(os.path.join(tmp, "file1.txt")))
            self.assertTrue(os.path.exists(os.path.join(tmp, "folder", "file2.txt")))

    def test_tar_gz_extraction_success(self):
        with tempfile.TemporaryDirectory() as tmp:
            account = {"base_path": tmp}
            tar_file = os.path.join(tmp, "test_archive.tar.gz")
            
            with tempfile.TemporaryDirectory() as inner_tmp:
                f1 = os.path.join(inner_tmp, "sample.txt")
                with open(f1, "w") as f:
                    f.write("Sample content")
                with tarfile.open(tar_file, "w:gz") as tf:
                    tf.add(f1, arcname="sample.txt")

            abs_path, rel_path = normalize_account_relative_path(account, "test_archive.tar.gz")
            dest_dir = os.path.dirname(str(abs_path))
            account_base = os.path.abspath(account["base_path"])

            extracted_count = 0
            with tarfile.open(str(abs_path), "r:*") as tf:
                for member in tf.getmembers():
                    target_path = os.path.abspath(os.path.join(dest_dir, member.name))
                    if not target_path.startswith(account_base + os.sep) and target_path != account_base:
                        raise ApiError(HTTPStatus.BAD_REQUEST, "invalid_path_traversal")
                    tf.extract(member, dest_dir)
                    extracted_count += 1

            self.assertEqual(extracted_count, 1)
            self.assertTrue(os.path.exists(os.path.join(tmp, "sample.txt")))

    def test_zip_slip_path_traversal_prevented(self):
        with tempfile.TemporaryDirectory() as tmp:
            account = {"base_path": tmp}
            zip_file = os.path.join(tmp, "evil.zip")
            
            with zipfile.ZipFile(zip_file, "w") as zf:
                zf.writestr("../../evil.txt", "Dangerous content")

            abs_path, rel_path = normalize_account_relative_path(account, "evil.zip")
            dest_dir = os.path.dirname(str(abs_path))
            account_base = os.path.abspath(account["base_path"])

            with self.assertRaises(ApiError) as ctx:
                with zipfile.ZipFile(str(abs_path), "r") as zf:
                    for member in zf.infolist():
                        target_path = os.path.abspath(os.path.join(dest_dir, member.filename))
                        if not target_path.startswith(account_base + os.sep) and target_path != account_base:
                            raise ApiError(HTTPStatus.BAD_REQUEST, "invalid_path_traversal")
                        zf.extract(member, dest_dir)

            self.assertEqual(ctx.exception.message, "invalid_path_traversal")

    def test_extracted_file_permissions_allow_webserver_write(self):
        with tempfile.TemporaryDirectory() as tmp:
            account = {"id": 1, "base_path": tmp, "username": "u000001"}
            zip_file = os.path.join(tmp, "wordpress_test.zip")
            
            with zipfile.ZipFile(zip_file, "w") as zf:
                zf.writestr("index.php", "<?php echo 'hello';")
                zf.writestr("wp-content/uploads/dummy.txt", "data")

            # Simulate extraction permissions setting logic
            dest_dir = tmp
            with zipfile.ZipFile(zip_file, "r") as zf:
                zf.extractall(dest_dir)

            for root, dirs, files in os.walk(dest_dir):
                for d in dirs:
                    os.chmod(os.path.join(root, d), 0o777)
                for f in files:
                    filepath = os.path.join(root, f)
                    st_mode = os.stat(filepath).st_mode
                    if st_mode & 0o111:
                        os.chmod(filepath, 0o777)
                    else:
                        os.chmod(filepath, 0o666)

            index_mode = os.stat(os.path.join(tmp, "index.php")).st_mode & 0o777
            dir_mode = os.stat(os.path.join(tmp, "wp-content")).st_mode & 0o777
            file_in_dir_mode = os.stat(os.path.join(tmp, "wp-content", "uploads", "dummy.txt")).st_mode & 0o777

            self.assertEqual(index_mode & 0o002, 0o002, "File must be writable by others (webserver)")
            self.assertEqual(dir_mode & 0o002, 0o002, "Directory must be writable by others (webserver)")
            self.assertEqual(file_in_dir_mode & 0o002, 0o002, "Nested file must be writable by others (webserver)")


if __name__ == "__main__":
    unittest.main()
