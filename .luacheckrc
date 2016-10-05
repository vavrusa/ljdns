std = "luajit"
ignore = { "211", "212", "411", "412", "421", "431" }
new_globals = {"bytes", "sample_keys", "ngx"}
-- Extend environment for unit tests
files["spec"] = {
	std = "+busted",
}