using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using Crestron.SimplSharp;
using SSMono.Threading;

namespace Crestron.SimplSharp.CrestronIO
	{
	public static class AsyncCallbackExtensions
		{
		public static IAsyncResult BeginInvokeEx (this AsyncCallback cb, IAsyncResult ar, AsyncCallback callback, object @object)
			{
			var newAr = new AsyncResult {AsyncState = @object, AsyncDelegate = cb};
			var tup = Tuple.Create (ar, callback, newAr);

			ThreadPool.QueueUserWorkItem (DoCallback, tup);

			return newAr;
			}

		public static void EndInvokeEx (this AsyncCallback cb, AsyncResult ar)
			{
			if (ar.EndInvokeCalled)
				throw new InvalidOperationException ("EndInvoke already called");

			ar.EndInvokeCalled = true;

			if (!ar.CompletedSynchronously)
				ar.AsyncWaitHandle.WaitOne ();
			}

		private static void DoCallback (object state)
			{
			var tup = (Tuple<IAsyncResult, AsyncCallback, AsyncResult>)state;
			var newAr = tup.Item3;

			((AsyncCallback)newAr.AsyncDelegate) (tup.Item1);

			((ManualResetEvent)newAr.AsyncWaitHandle).Set ();
			newAr.IsCompleted = true;

			if (tup.Item2 != null)
				tup.Item2 (newAr);
			}
		}

	public class AsyncResult : IAsyncResult
		{
		internal AsyncResult ()
			{
			AsyncWaitHandle =  new ManualResetEvent (false);
			}

		public object AsyncDelegate
			{
			get;
			internal set;
			}

		public bool EndInvokeCalled
			{
			get;
			internal set;
			}

		#region IAsyncResult Members

		public object AsyncState
			{
			get;
			internal set;
			}

		public CEventHandle AsyncWaitHandle
			{
			get;
			private set;
			}

		public bool CompletedSynchronously
			{
			get;
			internal set;
			}

		public object InnerObject
			{
			get;
			internal set;
			}

		public bool IsCompleted
			{
			get;
			internal set;
			}

		#endregion
		}
	}