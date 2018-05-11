// WebCamStillCapture - A simple library for capturing still images from a webcam
//
// Copyright © 2009 Justin Cherniak
//
// This library is free software; you can redistribute it and/or modify it
// under the terms of the GNU Lesser General Public License as published by
// the Free Software Foundation; either version 2.1 of the License, or (at
// your option) any later version.
//
// This library is distributed in the hope that it will be useful, but WITHOUT
// ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
// FITNESS FOR A PARTICULAR PURPOSE.  See the GNU Lesser General Public
// License (COPYING.txt) for more details.
//
// You should have received a copy of the GNU Lesser General Public License
// along with this library; if not, write to the Free Software Foundation,
// Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
// Webcam-Capture - A simple library for capturing images from a webcam
//
// Copyright © 2009 Justin Cherniak
//
// This library is free software; you can redistribute it and/or modify it
// under the terms of the GNU Lesser General Public License as published by
// the Free Software Foundation; either version 2.1 of the License, or (at
// your option) any later version.
//
// This library is distributed in the hope that it will be useful, but WITHOUT
// ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
// FITNESS FOR A PARTICULAR PURPOSE.  See the GNU Lesser General Public
// License (COPYING.txt) for more details.
//
// You should have received a copy of the GNU Lesser General Public License
// along with this library; if not, write to the Free Software Foundation,
// Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA

using System;
using System.Drawing;
using System.Windows.Forms;
using Win32Sharp;

namespace WebCamCapture
{
	public class WebCam : IDisposable
	{
		private int m_index;
		private IntPtr m_handle;
		private IntPtr m_parentHandle;
		private int m_width, m_height;

		public WebCam(int deviceIndex, IntPtr parentHandle, int width, int height, bool showWindow)
		{
			m_width = width;
			m_height = height;
			m_index = deviceIndex;
			m_parentHandle = parentHandle;

			if (m_parentHandle == IntPtr.Zero)
				throw new NullReferenceException("parentHandle cannot be 0");

			WindowStyle windowStyle = WindowStyle.WS_CHILD;
			if (showWindow)
				windowStyle |= WindowStyle.WS_VISIBLE;

			m_handle = ApiFunctions.capCreateCaptureWindow("WebCam " + deviceIndex,
				windowStyle, 0, 0, width, height, parentHandle, 0);

			if (m_handle == IntPtr.Zero)
				throw new InvalidOperationException("Error creating camera window");

			// Initialize Camera
			if (ApiFunctions.SendMessage(m_handle, CaptureMessage.WM_CAP_DRIVER_CONNECT,
				new IntPtr(deviceIndex), IntPtr.Zero) == IntPtr.Zero)
				throw new InvalidOperationException("Error connecting to camera");

			// Enable preview mode, ensuring our callback will be called
			if (ApiFunctions.SendMessage(m_handle, CaptureMessage.WM_CAP_SET_SCALE,
				new IntPtr(-1), IntPtr.Zero) == IntPtr.Zero)
				throw new InvalidOperationException("Error disabling scaling");
			if (ApiFunctions.SendMessage(m_handle, CaptureMessage.WM_CAP_SET_PREVIEWRATE,
				new IntPtr(100), IntPtr.Zero) == IntPtr.Zero)
				throw new InvalidOperationException("Error setting preview rate");
			if (ApiFunctions.SendMessage(m_handle, CaptureMessage.WM_CAP_SET_PREVIEW,
				new IntPtr(-1), IntPtr.Zero) == IntPtr.Zero)
				throw new InvalidOperationException("Error enabling preview mode.");
		}

		public Image TakePicture()
		{
			if (m_handle == IntPtr.Zero)
				throw new ObjectDisposedException("WebCam");

			IDataObject oldData = Clipboard.GetDataObject();

			try
			{
				if (ApiFunctions.SendMessage(m_handle, CaptureMessage.WM_CAP_EDIT_COPY,
					IntPtr.Zero, IntPtr.Zero) == IntPtr.Zero)
					throw new InvalidOperationException("Error copying image to clipboard");

				if (!Clipboard.ContainsImage())
					throw new InvalidOperationException("No image on clipboard");

				return Clipboard.GetImage();
			}
			finally
			{
				Clipboard.SetDataObject(oldData);
			}
		}

		public void Stop()
		{
			if (m_handle != IntPtr.Zero)
			{
				ApiFunctions.SendMessage(m_handle, CaptureMessage.WM_CAP_DRIVER_DISCONNECT,
					IntPtr.Zero, IntPtr.Zero);
				ApiFunctions.DestroyWindow(m_handle);

				m_handle = IntPtr.Zero;
			}

			GC.SuppressFinalize(this);
		}

		#region IDisposable Members

		~WebCam()
		{
			Stop();
		}

		public void Dispose()
		{
			Stop();
		}

		#endregion
	}
}
