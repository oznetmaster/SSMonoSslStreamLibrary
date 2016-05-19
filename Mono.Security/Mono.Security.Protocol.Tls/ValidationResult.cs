using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using Crestron.SimplSharp;

namespace Mono.Security.Protocol.Tls
	{
#if INSIDE_SYSTEM
	internal
#else
	public
#endif
 class ValidationResult
		{
		bool trusted;
		bool user_denied;
		int error_code;

		public ValidationResult (bool trusted, bool user_denied, int error_code)
			{
			this.trusted = trusted;
			this.user_denied = user_denied;
			this.error_code = error_code;
			}

		public bool Trusted
			{
			get { return trusted; }
			}

		public bool UserDenied
			{
			get { return user_denied; }
			}

		public int ErrorCode
			{
			get { return error_code; }
			}
		}
	}