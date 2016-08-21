std = "luajit"
ignore = { "211", "212", "411", "412", "421", "431" }
-- Extend environment for unit tests
files["spec"] = {
	std = "+busted",
}