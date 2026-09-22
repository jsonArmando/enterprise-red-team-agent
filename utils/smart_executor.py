import logging, os, signal, subprocess, tempfile, time
from pathlib import Path
logger=logging.getLogger("EnterpriseAgent")
class SmartCommandExecutor:
    def __init__(self,timeout_minutes=20,poll_interval=30):self.timeout_minutes=timeout_minutes;self.poll_interval=poll_interval
    def execute_with_polling(self,command,cwd=None):
        start=time.monotonic(); limit=self.timeout_minutes*60
        if cwd:
            try: Path(cwd).mkdir(parents=True,exist_ok=True)
            except OSError as e: logger.warning("[executor] cwd unavailable (%s): %s",cwd,e); cwd=None
        with tempfile.TemporaryDirectory(prefix="enterprise-agent-") as d:
            out,err=Path(d)/"stdout.log",Path(d)/"stderr.log"
            with out.open("w+",encoding="utf-8") as so,err.open("w+",encoding="utf-8") as se:
                # stdin=DEVNULL: any tool that would otherwise block on a
                # password/confirmation prompt gets EOF and fails fast instead
                # of hanging until the command timeout.
                kw={"shell":True,"stdin":subprocess.DEVNULL,"stdout":so,"stderr":se,"text":True}
                if cwd:kw["cwd"]=cwd
                if os.name=="posix":kw["start_new_session"]=True
                p=subprocess.Popen(command,**kw)
                while p.poll() is None:
                    elapsed=time.monotonic()-start
                    if elapsed>limit:
                        self._terminate(p); return self._result(out,err,-9,"timeout_killed")
                    time.sleep(self.poll_interval)
                return self._result(out,err,p.returncode,"completed" if p.returncode==0 else "failed")
    @staticmethod
    def _result(out,err,code,status):
        return {"stdout":out.read_text(encoding="utf-8",errors="replace"),"stderr":err.read_text(encoding="utf-8",errors="replace"),"returncode":code,"status":status}
    @staticmethod
    def _terminate(p):
        try:
            if os.name=="posix":
                os.killpg(p.pid,signal.SIGTERM); time.sleep(1)
                if p.poll() is None:os.killpg(p.pid,signal.SIGKILL)
            else:p.kill()
        except (ProcessLookupError,Exception):pass
