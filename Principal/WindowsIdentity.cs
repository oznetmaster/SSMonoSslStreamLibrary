//
// System.Security.Principal.WindowsIdentity
//
// Authors:
//      Gonzalo Paniagua Javier (gonzalo@ximian.com)
//	Sebastien Pouliot (sebastien@ximian.com)
//
// (C) 2002 Ximian, Inc (http://www.ximian.com)
// Portions (C) 2003 Motus Technologies Inc. (http://www.motus.com)
// Copyright (C) 2004-2005 Novell, Inc (http://www.novell.com)
//
// Permission is hereby granted, free of charge, to any person obtaining
// a copy of this software and associated documentation files (the
// "Software"), to deal in the Software without restriction, including
// without limitation the rights to use, copy, modify, merge, publish,
// distribute, sublicense, and/or sell copies of the Software, and to
// permit persons to whom the Software is furnished to do so, subject to
// the following conditions:
// 
// The above copyright notice and this permission notice shall be
// included in all copies or substantial portions of the Software.
// 
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
// EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
// MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
// NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE
// LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION
// OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION
// WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
//

using System;
using System.Runtime.InteropServices;
#if SSHARP
using SSMono.Security.Permissions;
using Crestron.SimplSharp.CrestronAuthentication;
using CA = Crestron.SimplSharp.CrestronAuthentication;
using Token = SSMono.Security.Principal.UserToken;
using System.Collections.Generic;
#else
using System.Runtime.CompilerServices;
using System.Runtime.Serialization;
using System.Security.Permissions;
using Token = System.IntPtr;
#endif

#if SSHARP
namespace SSMono.Security.Principal
#else
namespace System.Security.Principal
#endif
	{
	[Serializable]
	[ComVisible (true)]
	public class WindowsIdentity :
#if NET_4_5
	System.Security.Claims.ClaimsIdentity,
#endif
		IIdentity, 
#if !NETCF
		IDeserializationCallback, ISerializable,
#endif
		IDisposable
		{
		private Token _token;
		private string _type;
		private WindowsAccountType _account;
		private bool _authenticated;
		private string _name;
#if !NETCF
		private SerializationInfo _info;
#endif

		static private readonly Token invalidWindows = default (Token);

#if NET_4_5
		[NonSerialized]
		public new const string DefaultIssuer = "AD AUTHORITY";
#endif

		[SecurityPermission (SecurityAction.Demand, ControlPrincipal = true)]
		public WindowsIdentity (Token userToken)
			: this (userToken, null, WindowsAccountType.Normal, false)
			{
			}

		[SecurityPermission (SecurityAction.Demand, ControlPrincipal = true)]
		public WindowsIdentity (Token userToken, string type)
			: this (userToken, type, WindowsAccountType.Normal, false)
			{
			}

		[SecurityPermission (SecurityAction.Demand, ControlPrincipal = true)]
		public WindowsIdentity (Token userToken, string type, WindowsAccountType acctType)
			: this (userToken, type, acctType, false)
			{
			}

		[SecurityPermission (SecurityAction.Demand, ControlPrincipal = true)]
		public WindowsIdentity (Token userToken, string type, WindowsAccountType acctType, bool isAuthenticated)
			{
			_type = type;
			_account = acctType;
			_authenticated = isAuthenticated;
			_name = null;
			// last - as it can override some fields
			SetToken (userToken);
			}

		[SecurityPermission (SecurityAction.Demand, ControlPrincipal = true)]
		public WindowsIdentity (string sUserPrincipalName)
			: this (sUserPrincipalName, null)
			{
			}

		[SecurityPermission (SecurityAction.Demand, ControlPrincipal = true)]
		public WindowsIdentity (string sUserPrincipalName, string type)
			{
			if (sUserPrincipalName == null)
				throw new NullReferenceException ("sUserPrincipalName");

			// TODO: Windows 2003 compatibility should be done in runtime
			Token token = GetUserToken (sUserPrincipalName);
			if ((!Environment.IsUnix) && (token == default(Token)))
				{
				throw new ArgumentException ("only for Windows Server 2003 +");
				}

			_authenticated = true;
			_account = WindowsAccountType.Normal;
			_type = type;
			// last - as it can override some fields
			SetToken (token);
			}

#if !NETCF
		[SecurityPermission (SecurityAction.Demand, ControlPrincipal = true)]
		public WindowsIdentity (SerializationInfo info, StreamingContext context)
			{
			_info = info;
			}
#endif

		[ComVisible (false)]
		public void Dispose ()
			{
#if SSHARP
			if (_token != default (Token))
				CA.Authentication.ReleaseAuthenticationToken (_token);
#endif
			_token = default (Token);
			}

		[ComVisible (false)]
		protected virtual void Dispose (bool disposing)
			{
#if SSHARP
			if (_token != default (Token))
				CA.Authentication.ReleaseAuthenticationToken (_token);
#endif
			_token = default (Token);
			}
		// static methods

		public static WindowsIdentity GetAnonymous ()
			{
			WindowsIdentity id = null;
			if (Environment.IsUnix)
				{
				id = new WindowsIdentity ("nobody")
					{
					_account = WindowsAccountType.Anonymous,
					_authenticated = false,
					_type = String.Empty
					};
				// special case
				}
			else
				{
				id = new WindowsIdentity (default (Token), String.Empty, WindowsAccountType.Anonymous, false)
					{
					_name = String.Empty
					};
				// special case (don't try to resolve the name)
				}
			return id;
			}

		public static WindowsIdentity GetCurrent ()
			{
#if NETCF
			return GetAnonymous ();
#else
			return new WindowsIdentity (GetCurrentToken (), null, WindowsAccountType.Normal, true);
#endif
			}
		[MonoTODO ("need icall changes")]
		public static WindowsIdentity GetCurrent (bool ifImpersonating)
			{
			throw new NotImplementedException ();
			}

		[MonoTODO ("need icall changes")]
		public static WindowsIdentity GetCurrent (TokenAccessLevels desiredAccess)
			{
			throw new NotImplementedException ();
			}
		// methods

#if !NETCF
		public virtual WindowsImpersonationContext Impersonate ()
			{
			return new WindowsImpersonationContext (_token);
			}

		[SecurityPermission (SecurityAction.Demand, ControlPrincipal = true)]
		public static WindowsImpersonationContext Impersonate (Token userToken)
			{
			return new WindowsImpersonationContext (userToken);
			}
#endif

		// properties
#if NET_4_5
		sealed override
#endif
		public string AuthenticationType
			{
			get { return _type; }
			}

		public virtual bool IsAnonymous
			{
			get { return (_account == WindowsAccountType.Anonymous); }
			}

#if NET_4_5
		override
#else
		virtual
#endif
 public bool IsAuthenticated
			{
			get { return _authenticated; }
			}

		public virtual bool IsGuest
			{
			get { return (_account == WindowsAccountType.Guest); }
			}

		public virtual bool IsSystem
			{
			get { return (_account == WindowsAccountType.System); }
			}

#if NET_4_5
		override
#else
		virtual
#endif
 public string Name
			{
			get
				{
				if (_name == null)
					{
					// revolve name (runtime)
#if SSHARP
					_name = _token.UserName;
#else
					_name = GetTokenName (_token);
#endif
					}
				return _name;
				}
			}

		public virtual Token Token
			{
			get { return _token; }
			}
		[MonoTODO ("not implemented")]
		public IdentityReferenceCollection Groups
			{
			get { throw new NotImplementedException (); }
			}

		[MonoTODO ("not implemented")]
		[ComVisible (false)]
		public TokenImpersonationLevel ImpersonationLevel
			{
			get { throw new NotImplementedException (); }
			}

		[MonoTODO ("not implemented")]
		[ComVisible (false)]
		public SecurityIdentifier Owner
			{
			get { throw new NotImplementedException (); }
			}

		[MonoTODO ("not implemented")]
		[ComVisible (false)]
		public SecurityIdentifier User
			{
			get { throw new NotImplementedException (); }
			}

#if !NETCF
		void IDeserializationCallback.OnDeserialization (object sender)
			{
			_token = (IntPtr)_info.GetValue ("m_userToken", typeof (IntPtr));
			// can't trust this alone - we must validate the token
			_name = _info.GetString ("m_name");
			if (_name != null)
				{
				// validate token by comparing names
				string name = GetTokenName (_token);
				if (name != _name)
					throw new SerializationException ("Token-Name mismatch.");
				}
			else
				{
				// validate token by getting name
				_name = GetTokenName (_token);
				if (_name == null)
					throw new SerializationException ("Token doesn't match a user.");
				}
			_type = _info.GetString ("m_type");
			_account = (WindowsAccountType)_info.GetValue ("m_acctType", typeof (WindowsAccountType));
			_authenticated = _info.GetBoolean ("m_isAuthenticated");
			}

		void ISerializable.GetObjectData (SerializationInfo info, StreamingContext context)
			{
			info.AddValue ("m_userToken", _token);
			// can be null when not resolved
			info.AddValue ("m_name", _name);
			info.AddValue ("m_type", _type);
			info.AddValue ("m_acctType", _account);
			info.AddValue ("m_isAuthenticated", _authenticated);
			}
#endif

		private void SetToken (Token token)
			{
			if (Environment.IsUnix)
				{

				_token = token;
				// apply defaults
				if (_type == null)
					_type = "POSIX";
				// override user choice in this specific case
				if (_token == default (Token))
					_account = WindowsAccountType.System;
				}
			else
				{
				if ((token == invalidWindows) && (_account != WindowsAccountType.Anonymous))
					throw new ArgumentException ("Invalid token");

				_token = token;
				// apply defaults
				if (_type == null)
					_type = "NTLM";
				}
			}

#if MONO
		// see mono/mono/metadata/security.c for implementation

		// Many people use reflection to get a user's roles - so many 
		// that's it's hard to say it's an "undocumented" feature -
		// so we also implement it in Mono :-/
		// http://www.dotnet247.com/247reference/msgs/39/195403.aspx
		[MethodImplAttribute (MethodImplOptions.InternalCall)]
		internal extern static string[] _GetRoles (IntPtr token);

		[MethodImplAttribute (MethodImplOptions.InternalCall)]
		internal extern static IntPtr GetCurrentToken ();

		[MethodImplAttribute (MethodImplOptions.InternalCall)]
		private extern static string GetTokenName (IntPtr token);

		[MethodImplAttribute (MethodImplOptions.InternalCall)]
		private extern static IntPtr GetUserToken (string username);
#endif

#if SSHARP
		private static UserToken GetUserToken (string username)
			{
			return CA.Authentication.GetAuthenticationToken (username, String.Empty);
			}

		private static readonly string[] Roles = new string[] { "No Access", "Connect", "User", "Operator", "Programmer", "Administrator" };
		internal static string[] _GetRoles (Token token)
			{
			var listRoles = new List<string> ();
			var level = token.Access;

			if (level >= CA.Authentication.UserAuthenticationLevelEnum.Connect)
				{
				listRoles.Add ("Connect");
				if (level >= CA.Authentication.UserAuthenticationLevelEnum.User)
					{
					listRoles.Add ("User");
					if (level >= CA.Authentication.UserAuthenticationLevelEnum.Operator)
						{
						listRoles.Add ("Operator");
						if (level >= CA.Authentication.UserAuthenticationLevelEnum.Programmer)
							{
							listRoles.Add ("Programmer");
							if (level >= CA.Authentication.UserAuthenticationLevelEnum.Administrator)
								listRoles.Add ("Administrator");
							}
						}
					}
				}

			return listRoles.ToArray ();
			}
#endif
		}
	}
