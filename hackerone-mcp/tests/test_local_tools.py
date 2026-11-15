import asyncio
from pathlib import Path
import tempfile
import unittest


class LocalToolTests(unittest.IsolatedAsyncioTestCase):
    async def test_tool_registration_and_offline_calculation(self):
        from mcp.server.fastmcp import FastMCP
        from hackerone_mcp.local_tools import register_local_tools
        server=FastMCP("test")
        skill=Path(__file__).resolve().parents[2]/"bug-bounty"
        register_local_tools(server,environ={"BUG_BOUNTY_SKILL_DIR":str(skill)})
        tools=await server.list_tools()
        self.assertIn("bugbounty_score_cvss",[x.name for x in tools])
        result=await server.call_tool("bugbounty_score_cvss",{"vector":"CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:N/A:N"})
        self.assertIn("4.3",str(result))

    async def test_filesystem_tools_require_explicit_project_root(self):
        from mcp.server.fastmcp import FastMCP
        from hackerone_mcp.local_tools import register_local_tools
        server=FastMCP("test"); register_local_tools(server,environ={})
        with self.assertRaisesRegex(Exception,"BUG_BOUNTY_PROJECT_ROOT"):
            await server.call_tool("bugbounty_budget_status",{"project":"."})

    async def test_budget_state_cannot_escape_configured_root(self):
        from mcp.server.fastmcp import FastMCP
        from hackerone_mcp.local_tools import register_local_tools
        with tempfile.TemporaryDirectory() as temp:
            server=FastMCP("test")
            skill=Path(__file__).resolve().parents[2]/"bug-bounty"
            register_local_tools(server,environ={"BUG_BOUNTY_PROJECT_ROOT":temp,"BUG_BOUNTY_SKILL_DIR":str(skill)})
            await server.call_tool("bugbounty_budget_init",{"project":".","max_requests":3})
            status=await server.call_tool("bugbounty_budget_status",{"project":"."})
            self.assertIn("max_requests",str(status))
            with self.assertRaisesRegex(Exception,"outside"):
                await server.call_tool("bugbounty_budget_status",{"project":".."})
