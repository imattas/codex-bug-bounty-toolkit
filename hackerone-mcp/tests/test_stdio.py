"""Real subprocess MCP transport, with no credentials or external requests."""
import asyncio
import os
from pathlib import Path
import sys
import tempfile
import unittest

from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client


class StdioTests(unittest.IsolatedAsyncioTestCase):
    async def test_initialize_list_and_call_real_stdio_server(self):
        with tempfile.TemporaryDirectory() as temp:
            env=dict(os.environ)
            env.update({"H1_USERNAME":"","H1_API_TOKEN":"","H1_ENABLE_WRITES":"false","H1_DATA_DIR":str(Path(temp)/"data"),"BUG_BOUNTY_PROJECT_ROOT":temp,"BUG_BOUNTY_SKILL_DIR":str(Path(__file__).resolve().parents[2]/"bug-bounty")})
            params=StdioServerParameters(command=sys.executable,args=["-B","-m","hackerone_mcp"],env=env)
            async with asyncio.timeout(30):
                async with stdio_client(params) as (read,write):
                    async with ClientSession(read,write) as session:
                        initialized=await session.initialize()
                        self.assertTrue(initialized.serverInfo.name)
                        listed=await session.list_tools(); names={tool.name for tool in listed.tools}
                        self.assertIn("hackerone_prepare_submission",names)
                        self.assertIn("bugbounty_http_replay",names)
                        self.assertIn("bugbounty_browser_capture",names)
                        status=await session.call_tool("hackerone_status",{})
                        self.assertFalse(status.isError)
                        score=await session.call_tool("bugbounty_score_cvss",{"vector":"CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:N/A:N"})
                        self.assertFalse(score.isError); self.assertIn("4.3",str(score.content))
                        created=await session.call_tool("bugbounty_budget_init",{"project":".","max_requests":2})
                        self.assertFalse(created.isError)
                        escaped=await session.call_tool("bugbounty_budget_status",{"project":".."})
                        self.assertTrue(escaped.isError)
                        self.assertIn("outside",str(escaped.content))
