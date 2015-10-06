using System;
using System.Collections.Generic;
using System.Diagnostics.Contracts;
using System.Globalization;
using System.IdentityModel.Tokens;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.IdentityModel;
using Microsoft.IdentityModel.Protocols;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;

namespace HanzB2C.Security
{
    // This class is a temporary workaround for AAD B2C,
    // while our current libraries are unable to support B2C
    // out of the box.  For the original source code (with comments)
    // visit https://github.com/AzureAD/azure-activedirectory-identitymodel-extensions-for-dotnet/blob/master/src/Microsoft.IdentityModel.Protocol.Extensions/Configuration/ConfigurationManager.cs
    class PolicyConfigurationManager : IConfigurationManager<OpenIdConnectConfiguration>
    {
        public static readonly TimeSpan DefaultAutomaticRefreshInterval = new TimeSpan(5, 0, 0, 0);

        public static readonly TimeSpan DefaultRefreshInterval = new TimeSpan(0, 0, 0, 30);

        public static readonly TimeSpan MinimumAutomaticRefreshInterval = new TimeSpan(0, 0, 5, 0);

        public static readonly TimeSpan MinimumRefreshInterval = new TimeSpan(0, 0, 0, 1);

        private TimeSpan _automaticRefreshInterval = DefaultAutomaticRefreshInterval;
        private TimeSpan _refreshInterval = DefaultRefreshInterval;

        private readonly SemaphoreSlim _refreshLock;
        private readonly IDocumentRetriever _docRetriever;
        private readonly OpenIdConnectConfigurationRetriever _configRetriever;
        private Dictionary<string, PolicyConfiguration> _policyConfigurations;

        private class PolicyConfiguration
        {
            internal PolicyConfiguration(string policyName, string metadataAddress)
            {
                if (string.IsNullOrWhiteSpace(policyName))
                {
                    throw new ArgumentException(string.Format("{0} cannot be null, empty, or only whitespace.", nameof(policyName)));
                }

                if (string.IsNullOrWhiteSpace(metadataAddress))
                {
                    throw new ArgumentException(string.Format("{0} cannot be null, empty, or only whitespace.", nameof(metadataAddress)));
                }

                this.PolicyName = policyName;
                this.MetadataAddress = metadataAddress;
                this.SyncAfter = DateTimeOffset.MinValue;
                this.LastRefresh = DateTimeOffset.MinValue;
            }

            public string PolicyName { get; private set; }

            public string MetadataAddress { get; private set; }

            public DateTimeOffset SyncAfter { get; set; }

            public DateTimeOffset LastRefresh { get; set; }

            public OpenIdConnectConfiguration Configuration { get; set; }
        }

        public PolicyConfigurationManager()
            : this(new HttpDocumentRetriever())
        {
        }

        public PolicyConfigurationManager(IDocumentRetriever docRetriever)
        {
            if (docRetriever == null)
            {
                throw new ArgumentNullException("retriever");
            }

            _docRetriever = docRetriever;
            _configRetriever = new OpenIdConnectConfigurationRetriever();
            _refreshLock = new SemaphoreSlim(1);
            _policyConfigurations = new Dictionary<string, PolicyConfiguration>();
        }

        public void AddPolicy(string policyName, string metadataAddress)
        {
            if (string.IsNullOrWhiteSpace(policyName))
            {
                throw new ArgumentException(string.Format("{0} cannot be null, empty, or only whitespace.", nameof(policyName)));
            }

            if (string.IsNullOrWhiteSpace(metadataAddress))
            {
                throw new ArgumentException(string.Format("{0} cannot be null, empty, or only whitespace.", nameof(metadataAddress)));
            }

            if (_policyConfigurations.ContainsKey(policyName))
            {
                throw new ArgumentException(string.Format("A policy with key '{0}' has already been added.", policyName));
            }

            _policyConfigurations.Add(policyName, new PolicyConfiguration(policyName, metadataAddress));
        }

        public TimeSpan AutomaticRefreshInterval
        {
            get { return _automaticRefreshInterval; }
            set
            {
                if (value < MinimumAutomaticRefreshInterval)
                {
                    throw new ArgumentOutOfRangeException("value", value, string.Format(CultureInfo.InvariantCulture, ErrorMessages.IDX10107, MinimumAutomaticRefreshInterval, value));
                }
                _automaticRefreshInterval = value;
            }
        }

        public TimeSpan RefreshInterval
        {
            get { return _refreshInterval; }
            set
            {
                if (value < MinimumRefreshInterval)
                {
                    throw new ArgumentOutOfRangeException("value", value, string.Format(CultureInfo.InvariantCulture, ErrorMessages.IDX10106, MinimumRefreshInterval, value));
                }
                _refreshInterval = value;
            }
        }

        // Takes the ohter and copies it to source, preserving the source's multi-valued attributes as a running sum.
        private OpenIdConnectConfiguration MergeConfig(OpenIdConnectConfiguration source, OpenIdConnectConfiguration other)
        {
            ICollection<string> existingAlgs = source.IdTokenSigningAlgValuesSupported;
            ICollection<SecurityKey> existingSigningKeys = source.SigningKeys;

            foreach (string alg in existingAlgs)
            {
                if (!other.IdTokenSigningAlgValuesSupported.Contains(alg))
                {
                    other.IdTokenSigningAlgValuesSupported.Add(alg);
                }
            }

            foreach (SecurityKey key in existingSigningKeys)
            {
                other.SigningKeys.Add(key);
            }

            return other;
        }

        // This non-policy specific method effectively gets the metadata for all policies specified in the constructor,
        // and merges their signing key metadata.  It selects the other metadata from one of the policies at random.
        // This is done so that the middleware can take an incoming id_token and validate it against all signing keys
        // for the app, selecting the appropriate signing key based on the key identifiers.
        public async Task<OpenIdConnectConfiguration> GetConfigurationAsync(CancellationToken cancel)
        {
            OpenIdConnectConfiguration configUnion = new OpenIdConnectConfiguration();
            Dictionary<string, PolicyConfiguration> clone = new Dictionary<string, PolicyConfiguration>(_policyConfigurations);

            foreach (KeyValuePair<string, PolicyConfiguration> entry in clone)
            {
                OpenIdConnectConfiguration config = await GetConfigurationByPolicyAsync(entry.Value, cancel);
                configUnion = MergeConfig(configUnion, config);
            }

            return configUnion;
        }

        private async Task<OpenIdConnectConfiguration> GetConfigurationByPolicyAsync(PolicyConfiguration policyConfiguration, CancellationToken cancel)
        {
            DateTimeOffset now = DateTimeOffset.UtcNow;

            DateTimeOffset sync = policyConfiguration.SyncAfter;
            OpenIdConnectConfiguration config = policyConfiguration.Configuration;

            if (config != null && sync > now)
            {
                return config;
            }

            await _refreshLock.WaitAsync(cancel);
            try
            {
                Exception retrieveEx = null;
                if (sync <= now)
                {
                    try
                    {
                        config = await OpenIdConnectConfigurationRetriever.GetAsync(policyConfiguration.MetadataAddress, cancel);
                        policyConfiguration.Configuration = config;
                        Contract.Assert(policyConfiguration.Configuration != null);
                        policyConfiguration.LastRefresh = now;
                        policyConfiguration.SyncAfter = now.UtcDateTime.Add(_automaticRefreshInterval);
                    }
                    catch (Exception ex)
                    {
                        retrieveEx = ex;
                        policyConfiguration.SyncAfter = now.UtcDateTime.Add(_automaticRefreshInterval < _refreshInterval ? _automaticRefreshInterval : _refreshInterval);
                    }
                }

                if (config == null)
                {
                    throw new InvalidOperationException(string.Format(CultureInfo.InvariantCulture, ErrorMessages.IDX10803, policyConfiguration.MetadataAddress ?? "null"), retrieveEx);
                }

                return config;
            }
            finally
            {
                _refreshLock.Release();
            }
        }

        public async Task<OpenIdConnectConfiguration> GetConfigurationByPolicyAsync(CancellationToken cancel, string policyId)
        {
            PolicyConfiguration policyConfiguration = null;
            if (!_policyConfigurations.TryGetValue(policyId, out policyConfiguration))
            {
                return null;
            }

            return await GetConfigurationByPolicyAsync(policyConfiguration, cancel);
        }

        public void RequestRefresh(string policyId)
        {
            PolicyConfiguration policyConfiguration = null;
            if (_policyConfigurations.TryGetValue(policyId, out policyConfiguration))
            {
                RequestRefresh(policyConfiguration);
            }
        }

        private void RequestRefresh(PolicyConfiguration policyConfiguration)
        {
            if (policyConfiguration == null)
            {
                throw new ArgumentNullException(nameof(policyConfiguration));
            }

            DateTimeOffset now = DateTimeOffset.UtcNow;
            if (now >= policyConfiguration.LastRefresh.UtcDateTime.Add(RefreshInterval))
            {
                policyConfiguration.SyncAfter = now;
            }
        }

        public void RequestRefresh()
        {
            foreach (KeyValuePair<string, PolicyConfiguration> entry in _policyConfigurations)
            {
                RequestRefresh(entry.Value);
            }
        }
    }

}
