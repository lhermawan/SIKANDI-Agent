import os
import logging
import shutil

logger = logging.getLogger(__name__)

class DiskManager:
    def __init__(self, safe_paths=None):
        # Default safe paths that can be scanned/deleted
        if safe_paths is None:
            self.safe_paths = [
                '/var/cache', 
                '/tmp', 
                '/var/log',
                '/var/www',        # Web directories (Laravel storage/logs, public/build)
                '/root/.npm',      # NPM global cache
                '/root/.cache'     # Other root caches (composer, yarn)
            ]
        else:
            self.safe_paths = safe_paths
            
    def _is_safe(self, target_path):
        target = os.path.abspath(target_path)
        for safe in self.safe_paths:
            safe_abs = os.path.abspath(safe)
            # Menggunakan commonpath untuk validasi hirarki direktori secara aman
            if os.path.commonpath([safe_abs, target]) == safe_abs:
                return True
        return False

    def scan_directories(self, paths, max_depth=3):
        results = []
        for path in paths:
            if not self._is_safe(path):
                logger.warning(f"Path {path} is not in safe paths list. Skipping scan.")
                continue
            
            if os.path.exists(path):
                results.append(self._get_tree(path, current_depth=0, max_depth=max_depth))
            else:
                logger.warning(f"Path {path} does not exist.")
        return results

    def _get_dir_size(self, path):
        total = 0
        try:
            for dirpath, _, filenames in os.walk(path):
                for f in filenames:
                    fp = os.path.join(dirpath, f)
                    if not os.path.islink(fp):
                        try:
                            total += os.path.getsize(fp)
                        except Exception:
                            pass
        except Exception:
            pass
        return total

    def _get_tree(self, path, current_depth=0, max_depth=3):
        tree = {
            "name": os.path.basename(path) or path,
            "path": path,
            "type": "directory" if os.path.isdir(path) else "file",
            "size": 0,
            "children": []
        }
        
        try:
            if os.path.isdir(path):
                if current_depth >= max_depth:
                    # Just calculate size, don't build children tree to avoid huge JSON payload
                    tree["size"] = self._get_dir_size(path)
                else:
                    for item in os.listdir(path):
                        item_path = os.path.join(path, item)
                        try:
                            child_tree = self._get_tree(item_path, current_depth + 1, max_depth)
                            if child_tree:
                                tree["children"].append(child_tree)
                                tree["size"] += child_tree["size"]
                        except PermissionError:
                            pass
            else:
                if not os.path.islink(path):
                    tree["size"] = os.path.getsize(path)
        except Exception as e:
            logger.debug(f"Error accessing {path}: {e}")
            
        return tree

    def delete_paths(self, paths):
        deleted = []
        failed = []
        for path in paths:
            if not self._is_safe(path):
                failed.append({"path": path, "reason": "Not in safe paths"})
                continue
                
            if not os.path.exists(path):
                failed.append({"path": path, "reason": "Path does not exist"})
                continue
                
            try:
                if os.path.isfile(path) or os.path.islink(path):
                    os.remove(path)
                elif os.path.isdir(path):
                    shutil.rmtree(path)
                deleted.append(path)
                logger.info(f"Successfully deleted {path}")
            except Exception as e:
                failed.append({"path": path, "reason": str(e)})
                logger.error(f"Failed to delete {path}: {e}")
                
        return {"deleted": deleted, "failed": failed}
