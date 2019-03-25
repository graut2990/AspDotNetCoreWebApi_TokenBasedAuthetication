using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace AspDotNetCoreWebApi_TokenBasedAuthetication.Model
{
    public class UserModel
    {
        public string Username { get; set; }
        public string EmailAddress { get; set; }

        public string Role { get; set; }
    }
}
