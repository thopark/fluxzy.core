﻿namespace Fluxzy.Desktop.Services.Models
{
    public class TrunkState
    {
        public TrunkState(
            List<ExchangeContainer> internalExchanges,
            List<ConnectionContainer> internalConnections)
        {
            Exchanges = internalExchanges;
            Connections = internalConnections;
            var agents =  new HashSet<Agent>();

            for (int index = 0; index < Exchanges.Count; index++)
            {
                var exchange = Exchanges[index];
                ExchangesIndexer[exchange.Id] = index;
                MaxExchangeId = exchange.Id;

                if (exchange.ExchangeInfo.Agent != null) {
                    agents.Add(exchange.ExchangeInfo.Agent);
                }
            }

            for (var index = 0; index < Connections.Count; index++)
            {
                var connection = Connections[index];
                ConnectionsIndexer[connection.Id] = index;
                MaxConnectionId = connection.Id;
            }

            Agents = agents.OrderBy(r => r.FriendlyName).ToList(); 
        }
        

        public TrunkState(
            IEnumerable<ExchangeContainer> internalExchanges,
            IEnumerable<ConnectionContainer> internalConnections)
            : this(internalExchanges.OrderBy(r => r.Id).ToList(), internalConnections.OrderBy(r => r.Id).ToList())
        {
        }

        public List<ExchangeContainer> Exchanges { get; }


        public List<ConnectionContainer> Connections { get; }
        
        public List<Agent> Agents { get; set; }

        public int MaxExchangeId { get;  }

        public int MaxConnectionId { get;  }

        /// <summary>
        /// Map a exchange Identifier to its position (index) on Exchanges list
        /// </summary>
        public Dictionary<int, int> ExchangesIndexer { get; } = new();

        /// <summary>
        /// same algorithm as ExchangesIndexer 
        /// </summary>
        public Dictionary<int, int> ConnectionsIndexer { get; } = new();
        
        public static TrunkState Empty()
        {
            return new TrunkState(Array.Empty<ExchangeContainer>(), Array.Empty<ConnectionContainer>()); 
        }

        public TrunkState ApplyFilter(FilteredExchangeState state)
        {
            return new TrunkState(Exchanges.Where(e => state.Exchanges.Contains(e.Id)), Connections); 
        }
    }
}