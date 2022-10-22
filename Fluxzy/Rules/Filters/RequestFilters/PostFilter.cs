﻿// Copyright © 2022 Haga Rakotoharivelo

using System.IO;

namespace Fluxzy.Rules.Filters.RequestFilters
{
    public class PostFilter : MethodFilter
    {
        public PostFilter() : base("POST")
        {
        }

        public override string GenericName => "POST only";

        public override bool Common { get; set; } = true;

        public override string ShortName => "post";

        public override bool PreMadeFilter => true;
    }


    public class PatchFilter : MethodFilter
    {
        public PatchFilter() : base("PATCH")
        {
        }

        public override string GenericName => "PATCH only";

        public override string ShortName => "patch";
        public override bool PreMadeFilter => true;
    }

    public class DeleteFilter : MethodFilter
    {
        public DeleteFilter() : base("DELETE")
        {
        }

        public override string GenericName => "DELETE only";

        public override string ShortName => "del";
        public override bool PreMadeFilter => true;
    }

    public class PutFilter : MethodFilter
    {
        public PutFilter() : base("PUT")
        {
        }

        public override string GenericName => "PUT only";

        public override string ShortName => "put";
        public override bool PreMadeFilter => true;
    }
}