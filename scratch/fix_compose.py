import glob

for filepath in glob.glob("/root/MangoPanel/user_files/accounts/*/.runtime/stack/docker-compose.yml"):
    lines = open(filepath, "r", encoding="utf-8").readlines()
    new_lines = []
    for line in lines:
        if line.strip().startswith("entrypoint:"):
            continue
        if line.strip().startswith("command: [\"--config\""):
            indent = line[:line.find("command:")]
            new_lines.append(indent + 'entrypoint: ["/bin/sh", "-c", \'umask 0000 && exec /init.sh "$$@"\', "--"]\n')
        new_lines.append(line)
    open(filepath, "w", encoding="utf-8").writelines(new_lines)
    print("Fixed:", filepath)
