using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using Crestron.SimplSharp;
using System.Runtime.InteropServices;

namespace SSMono.Security.Principal
	{
	using Crestron.SimplSharp.CrestronAuthentication;

	[StructLayout (LayoutKind.Sequential)]
	public struct UserToken
		{
		private Authentication.UserToken _userToken;

		public UserToken (Authentication.UserToken userToken)
			{
			_userToken = userToken;
			}

		public string UserName
			{
			get { return _userToken.UserName; }
			}
		public string Password
			{
			get { return _userToken.Password; }
			}
		public Authentication.UserAuthenticationLevelEnum Access
			{
			get { return _userToken.Access; }
			}
		public int ADConnect
			{
			get { return _userToken.ADConnect; }
			}
		public bool Valid
			{
			get { return _userToken.Valid; }
			}

		public override bool Equals (object obj)
			{
			if (obj is UserToken)
				{
				var ut = (UserToken)obj;
				return UserName == ut.UserName && Password == ut.Password && Access == ut.Access && ADConnect == ut.ADConnect && Valid == ut.Valid;
				}

			return false;
			}

		public override int GetHashCode ()
			{
			return UserName.GetHashCode () ^ Password.GetHashCode () ^ Access.GetHashCode () ^ ADConnect.GetHashCode () ^ Valid.GetHashCode ();
			}

		public static bool operator== (UserToken t1, UserToken t2)
			{
			return t1.UserName == t2.UserName && t1.Password == t2.Password && t1.Access == t2.Access && t1.ADConnect == t2.ADConnect && t1.Valid == t2.Valid;
			}

		public static bool operator!= (UserToken t1, UserToken t2)
			{
			return t1.UserName != t2.UserName || t1.Password != t2.Password || t1.Access != t2.Access || t1.ADConnect != t2.ADConnect || t1.Valid != t2.Valid;
			}

		public static implicit operator UserToken (Authentication.UserToken cut)
			{
			return new UserToken (cut);
			}

		public static implicit operator Authentication.UserToken (UserToken ut)
			{
			return ut._userToken;
			}

		}
	}