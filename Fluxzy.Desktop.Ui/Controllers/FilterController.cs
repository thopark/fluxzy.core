﻿// Copyright © 2022 Haga Rakotoharivelo

using Fluxzy.Desktop.Services;
using Fluxzy.Desktop.Services.Filters;
using Fluxzy.Desktop.Services.Models;
using Fluxzy.Rules.Filters;
using Microsoft.AspNetCore.Mvc;

namespace Fluxzy.Desktop.Ui.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class FilterController : ControllerBase
    {
        [HttpPost("validate")]
        public ActionResult<Filter> Validate(Filter filter)
        {
            return filter;
        }

        [HttpGet("templates")]
        public ActionResult<List<FilterTemplate>> GetTemplates([FromServices] FilterTemplateManager templateManager)
        {
            return templateManager.ReadAvailableTemplates();
        }

        [HttpGet("templates/any")]
        public ActionResult<AnyFilter> GetTemplates()
        {
            return AnyFilter.Default;
        }

        [HttpPost("apply/regular")]
        public ActionResult<bool> ApplyToView(Filter filter,
            [FromServices] ActiveViewFilterManager activeViewFilterManager,
            [FromServices]
            TemplateToolBarFilterProvider filterProvider)
        {
            activeViewFilterManager.UpdateViewFilter(filter);
            filterProvider.SetNewFilter(filter);

            return true;
        }
        
        [HttpPost("apply/source")]
        public ActionResult<bool> ApplySourceFilterToView(Filter filter,
            [FromServices] ActiveViewFilterManager activeViewFilterManager,
            [FromServices]
            TemplateToolBarFilterProvider filterProvider)
        {
            activeViewFilterManager.UpdateSourceFilter(filter);
            filterProvider.SetNewFilter(filter);

            return true;
        }
        
        [HttpDelete("apply/source")]
        public ActionResult<bool> ApplyResetSourceFilterToView(
            [FromServices] ActiveViewFilterManager activeViewFilterManager,
            [FromServices]
            TemplateToolBarFilterProvider filterProvider)
        {
            activeViewFilterManager.UpdateSourceFilter(AnyFilter.Default);
            return true;
        }
    }
}
