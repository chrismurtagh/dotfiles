return {
  "neovim/nvim-lspconfig",
  dependencies = {
    { "mason-org/mason.nvim", opts ={} }
  },
  config = function()
    require('servers')
  end
}
