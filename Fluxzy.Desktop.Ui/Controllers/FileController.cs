﻿// Copyright © 2022 Haga Rakotoharivelo

using Echoes.Desktop.Ui.ViewModels;
using Fluxzy.Desktop.Services;
using Fluxzy.Desktop.Services.Models;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.SignalR;

namespace Echoes.Desktop.Ui.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class FileController : ControllerBase
    {
        private readonly GlobalFileManager _globalFileManager;
        private readonly UiStateManager _uiStateManager;

        public FileController(GlobalFileManager globalFileManager, UiStateManager uiStateManager )
        {
            _globalFileManager = globalFileManager;
            _uiStateManager = uiStateManager;
        }

        [HttpPost("new")]
        public async Task<ActionResult<UiState>> New()
        {
            await _globalFileManager.New();
            return _uiStateManager.GetUiState(); 
        }

        [HttpPost("open")]
        public async Task<ActionResult<UiState>> Open(FileOpeningViewModel model)
        {
            await _globalFileManager.Open(model.FileName);
            return _uiStateManager.GetUiState();
        }
    }
}