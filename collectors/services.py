import subprocess


class ServiceCollector:

    def collect(self):
        services = []

        try:
            result = subprocess.run(
                [
                    "systemctl",
                    "list-units",
                    "--type=service",
                    "--all",
                    "--no-pager",
                    "--no-legend",
                ],
                capture_output=True,
                text=True,
                timeout=10,
                check=False,
            )

            if result.returncode != 0:
                return []

            for line in result.stdout.splitlines():
                parts = line.split(None, 4)

                if len(parts) < 4:
                    continue

                unit = parts[0]
                load = parts[1]
                active = parts[2]
                sub = parts[3]
                description = parts[4] if len(parts) > 4 else ""

                if not unit.endswith(".service"):
                    continue

                services.append({
                    "name": unit.replace(".service", ""),
                    "status": active,
                    "sub_status": sub,
                    "load_status": load,
                    "description": description.strip(),
                })

        except Exception as e:
            print(f"Service collector error: {e}")

        return services