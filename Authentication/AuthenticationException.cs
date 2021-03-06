//
// System.Security.Authentication.AuthenticationException
//
// Author:
//   Joe Shaw (joe@ximian.com)
//   Miguel de Icaza (miguel@novell.com)
//   Sebastien Pouliot  <sebastien@ximian.com>
//
// Copyright (C) 2004, 2006 Novell, Inc (http://www.novell.com)
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

#if !NETCF
using System.Runtime.Serialization;
#endif

using System;

#if SSHARP
namespace SSMono.Security.Authentication
#else
namespace System.Security.Authentication
#endif
	{

	[Serializable]
	public class AuthenticationException : SystemException
		{

		public AuthenticationException ()
			: base (Locale.GetText ("Authentication exception."))
			{
			}

		public AuthenticationException (string message)
			: base (message)
			{
			}

		public AuthenticationException (string message, Exception innerException)
			: base (message, innerException)
			{
			}

#if !NETCF
		protected AuthenticationException (SerializationInfo serializationInfo, StreamingContext streamingContext)
			: base (serializationInfo, streamingContext)
			{
			}
#endif
		}
	}

