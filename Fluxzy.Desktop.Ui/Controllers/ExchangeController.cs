﻿// Copyright © 2022 Haga Rakotoharivelo

using Fluxzy.Formatters;
using Fluxzy.Formatters.Producers.ProducerActions.Actions;
using Microsoft.AspNetCore.Mvc;

namespace Fluxzy.Desktop.Ui.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class ExchangeController
    {
        public record SaveFileViewModel(string FileName); 

        private readonly ProducerFactory _producerFactory;
        public ExchangeController(
            ProducerFactory producerFactory)
        {
            _producerFactory = producerFactory;
        }

        [HttpPost("{exchangeId}/save-request-body")]
        public async Task<ActionResult<bool>> SaveRequestBody(
            int exchangeId,
            [FromBody] SaveFileViewModel body,
            [FromServices] SaveRequestBodyProducerAction action)
        {
            return await action.Do(exchangeId, body.FileName);
        }

        [HttpPost("{exchangeId}/save-multipart-Content")]
        public async Task<ActionResult<bool>> SaveMultipartContent(
            int exchangeId,
            [FromBody] SaveFileMultipartActionModel body,
            [FromServices] SaveFileMultipartAction action)
        {
            return await action.Do(exchangeId, body);
        }


        [HttpPost("{exchangeId}/save-response-body")]
        public async Task<ActionResult<bool>> SaveResponseBody(
            [FromServices] SaveResponseBodyAction action,
            int exchangeId, [FromBody] SaveFileViewModel body,
            [FromQuery(Name = "decode")] bool decode = true)
        {
            return await action.Do(exchangeId,decode, body.FileName);
        }
    }
}