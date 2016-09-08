using System;
using Microsoft.Xrm.Sdk;
using Microsoft.Xrm.Sdk.Query;
using Microsoft.Azure.KeyVault;
using System.Configuration;
using System.Net;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Security.Cryptography;
using System.Threading.Tasks;
using Microsoft.IdentityModel.Clients.ActiveDirectory;
using System.IO;
using Microsoft.Xrm.Sdk.Client;

namespace KeyVaultPlugin
{
    public class KeyVaultPlugin : IPlugin
	{
		public void Execute(IServiceProvider serviceProvider)
		{
			IPluginExecutionContext context = (IPluginExecutionContext)
					serviceProvider.GetService(typeof(IPluginExecutionContext));

			var organizationServiceFactory = (IOrganizationServiceFactory)
					serviceProvider.GetService(typeof (IOrganizationServiceFactory));

			AssertNull(context, "context");
			AssertNull(organizationServiceFactory, "organizationServiceFactory");

            var organizationService = organizationServiceFactory.CreateOrganizationService(context.UserId);

            AssertNull(organizationService, "organizationService");

            // Obtain the target entity from the input parmameters.
            Entity accountEntity = (Entity)context.InputParameters["Target"];
            
            //create new task for account set in 2 weeks in the future
            Entity contactAccountTask = new Entity("task");
            contactAccountTask["subject"] = "Check new account is happy";
            contactAccountTask["description"] = "Make contact with new customer. See if they are happy with service and resolve any issues.";
            contactAccountTask["scheduledstart"] = DateTime.Now.AddDays(14);
            contactAccountTask["scheduledend"] = DateTime.Now.AddDays(14);
            EntityReference entRef = new EntityReference("account", accountEntity.Id);
            contactAccountTask["regardingobjectid"] = entRef;

            // Create the task and this should be linked to the new account record
            organizationService.Create(contactAccountTask);


            // just create some dummy files and save on disk
            string logsFolder = Environment.ExpandEnvironmentVariables(@"%HOME%\LogFiles");
            Guid randomFileName = Guid.NewGuid();

            File.WriteAllText(Path.Combine(logsFolder, randomFileName.ToString()), "current time:" + DateTime.Now);
        }

        //the method that will be provided to the KeyVaultClient
        private async Task<string> GetToken(string authority, string resource, string scope)
        {
            var authContext = new AuthenticationContext(authority);
            ClientCredential clientCred = new ClientCredential("78a191c0-a24d-4508-a908-38709541c594",
                                                               "SFrnl8PhQESeEmn2HF+74BHENM16CguGONGLjtA1gEc=");
            AuthenticationResult result = await authContext.AcquireTokenAsync(resource, clientCred);

            if (result == null)
                throw new InvalidOperationException("Failed to obtain the JWT token");

            return result.AccessToken;
        }

        private void AssertNull(object obj, string msg)
		{
			if (obj == null)
				throw new  InvalidPluginExecutionException(msg);
		}
	}
}
