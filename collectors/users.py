import os
import pwd
import grp


class UserCollector:

    def collect(self):
        users = []

        try:
            for entry in pwd.getpwall():
                username = entry.pw_name
                uid = entry.pw_uid
                gid = entry.pw_gid
                home = entry.pw_dir
                shell = entry.pw_shell

                # Get primary group name
                try:
                    group_name = grp.getgrgid(gid).gr_name
                except KeyError:
                    group_name = str(gid)

                # Determine account type
                if uid == 0:
                    account_type = "root"
                elif uid < 1000:
                    account_type = "system"
                else:
                    account_type = "user"

                # Check whether login shell is available
                login_allowed = shell not in (
                    "/usr/sbin/nologin",
                    "/sbin/nologin",
                    "/bin/false",
                    "/usr/bin/false",
                )

                # Check sudo/admin privileges
                is_admin = self._is_admin(username)

                users.append({
                    "username": username,
                    "uid": uid,
                    "gid": gid,
                    "group": group_name,
                    "home": home,
                    "shell": shell,
                    "account_type": account_type,
                    "login_allowed": login_allowed,
                    "is_admin": is_admin,
                })

        except Exception as e:
            print(f"User collector error: {e}")

        return users

    def _is_admin(self, username):
        """
        Check whether the user belongs to sudo/admin groups.
        """

        try:
            groups = []

            for group in grp.getgrall():
                if username in group.gr_mem:
                    groups.append(group.gr_name)

            # Primary group
            try:
                user = pwd.getpwnam(username)

                primary_group = grp.getgrgid(
                    user.pw_gid
                ).gr_name

                groups.append(primary_group)

            except KeyError:
                pass

            return any(
                group in ("sudo", "admin", "wheel")
                for group in groups
            )

        except Exception:
            return False