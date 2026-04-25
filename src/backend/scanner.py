import subprocess
import json
import os

def run_ps_script(script_name, args=None):
    # execute a script from the scripts folder and return json
    script_path = os.path.join(os.path.dirname(__file__), 'scripts', script_name)
    
    if not os.path.exists(script_path):
        return {"error": f"Script not found: {script_name}"}

    cmd = ["powershell.exe", "-ExecutionPolicy", "Bypass", "-File", script_path]
    if args:
        cmd.extend(args)

    try:
        result = subprocess.run(cmd, capture_output=True, text=True, check=True, timeout=60)
        return json.loads(result.stdout)
    except subprocess.TimeoutExpired:
        return [] # return empty on timeout
    except subprocess.CalledProcessError as e:
        return {"error": f"Script failed: {e.stderr}"}
    except json.JSONDecodeError:
        return {"error": "Script output was not valid JSON"}

if __name__ == "__main__":
    # simple test for the executor foundation
    print("Scanner module initialized.")
