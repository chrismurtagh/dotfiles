-- ================================================================================================
-- TITLE : auto-commands
-- ABOUT : automatically run code on defined events (e.g. save, yank)
-- ================================================================================================

local capabilities = require("cmp_nvim_lsp").default_capabilities()
local on_attach = require("utils.lsp").on_attach

vim.lsp.config("lua_ls", {
	on_attach = on_attach,
	capabilities = capabilities,
	settings = {
		Lua = {
			diagnostics = {
				globals = { "vim" },
			},
			workspace = {
				library = {
					vim.fn.expand("$VIMRUNTIME/lua"),
					vim.fn.expand("$XDG_CONFIG_HOME") .. "/nvim/lua",
				},
			},
		},
	},
})

local luacheck = require("efmls-configs.linters.luacheck")
local stylua = require("efmls-configs.formatters.stylua")

local black = require("efmls-configs.formatters.black")
local flake8 = require("efmls-configs.linters.flake8")

local eslint_d = require("efmls-configs.linters.eslint_d")
local prettier = require("efmls-configs.formatters.prettier")

local fixjson = require("efmls-configs.formatters.fixjson")

vim.lsp.config("efm", {
	on_attach = on_attach,
	capabilities = capabilities,
	filetypes = {
		"lua",
		"python",
		"typescript",
		"typescriptreact",
		"javascript",
		"typescriptreact",
		"html",
		"dockerfile",
		"css",
		"markdown",
		"json",
		"jsonc",
	},
	init_options = {
		documentFormatting = true,
		documentRangeFormatting = true,
		hover = true,
		documentSymbol = true,
		codeAction = true,
		completion = true,
	},
	settings = {
		languages = {
			lua = { luacheck, stylua },
			python = { flake8, black },
			typescript = { eslint_d, prettier },
			typescriptreact = { eslint_d, prettier },
			javascript = { eslint_d, prettier },
			javascriptreact = { eslint_d, prettier },
			json = { fixjson, eslint_d },
			jsonc = { fixjson, eslint_d },
			markdown = { prettier },
			html = { prettier },
			dockerfile = { prettier },
			css = { prettier },
		},
	},
})

vim.lsp.enable({
	"lua_ls",
	"efm",
})

lspconfig.pyright.setup({
	on_attach = on_attach,
	capabilities = capabilities,
	filetypes = { "python" },
	settings = {
		pyright = {
			disableOrganizeImports = false,
			analysis = {
				autoSearchPaths = true,
				diagnosticMode = "workspace",
				useLibraryCodeForTypes = true,
				autoImportCompletions = true,
			},
		},
	},
})

lspconfig.ts_ls.setup({
	on_attach = on_attach,
	capabilities = capabilities,
	filetypes = {
		"typescript",
		"javascript",
		"javascriptreact",
		"typescriptreact",
	},
	settings = {
		typescript = {
			indentStyle = "space",
			indentSize = 2,
		},
	},
})
