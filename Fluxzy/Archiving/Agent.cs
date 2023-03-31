// Copyright 2021 - Haga Rakotoharivelo - https://github.com/haga-rak

using System;
using System.Net;
using Fluxzy.Misc;

namespace Fluxzy
{
    public class Agent
    {
        public Agent(int id, string friendlyName)
        {
            Id = id;
            FriendlyName = friendlyName;
        }

        public int Id { get; }

        public string FriendlyName { get; }

        protected bool Equals(Agent other)
        {
            return Id == other.Id && FriendlyName == other.FriendlyName;
        }

        public override string ToString()
        {
            return FriendlyName;
        }

        public override bool Equals(object? obj)
        {
            if (ReferenceEquals(null, obj))
                return false;

            if (ReferenceEquals(this, obj))
                return true;

            if (obj.GetType() != GetType())
                return false;

            return Equals((Agent) obj);
        }

        public override int GetHashCode()
        {
            return HashCode.Combine(Id, FriendlyName);
        }

        public static Agent Create(
            string userAgentValue,
            IPAddress localAddress,
            IUserAgentInfoProvider userAgentInfoProvider)
        {
            var id = CreateId(userAgentValue, localAddress);

            return new Agent(id, userAgentInfoProvider.GetFriendlyName(id, userAgentValue));
        }

        public static int CreateId(string userAgentValue, IPAddress localAddress)
        {
            var id = HashUtility.GetLongHash(userAgentValue);
            id ^= (ulong) localAddress.GetHashCode(); // WARNING: IPAddress GetHashCode is not stable

            unchecked {
                return (int) id;
            }
        }
    }
}
