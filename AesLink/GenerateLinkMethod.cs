// --------------------------------------------------------------------------------------------------------------------
// <copyright file="GenerateLinkMethod.cs" company="PerkinElmer Inc.">
//   Copyright (c) 2013 PerkinElmer Inc.,
//     940 Winter Street, Waltham, MA 02451.
//     All rights reserved.
//     This software is the confidential and proprietary information
//     of PerkinElmer Inc. ("Confidential Information"). You shall not
//     disclose such Confidential Information and may not use it in any way,
//     absent an express written license agreement between you and PerkinElmer Inc.
//     that authorizes such use.
// </copyright>
// --------------------------------------------------------------------------------------------------------------------
#region

using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using System.Web;
using Spotfire.Dxp.Application.Extension;
using Spotfire.Dxp.Data;
using Spotfire.Dxp.Data.Computations;

#endregion

namespace Com.PerkinElmer.Service.AesLink
{
    public sealed class GenerateLinkMethod : CustomRowMethod<string>
    {
        /// <summary>The name of the method as entered by the user in an expression.
        /// </summary>
        private const string MethodName = "AESLink";

        /// <summary>The namespace of the method.
        /// </summary>
        private const string Namespace = "Com.PerkinELmer.Service";

        /// <summary>A localized description on how to use the method and what the method does,
        /// this is shown to the user in some user interfaces.
        /// </summary>
        private static readonly string MethodDescription = "Create AES Link method.\n\nAESLink([uid],[uname],[orgid],[orgname],[pname],[pcid],[timestamp],[appointkey])";

        /// <summary>A localized name of the method as shown in some user interfaces.
        /// </summary>
        private static readonly string MethodDisplayName = "AES Link";

        /// <summary>The section that the method is part of.
        /// </summary>
        /// <remarks>Methods has to be part of a single section and this is used when listing all
        /// functions in user interfaces to make it easier for the user to find a specific method.
        /// Either choose one of the predefined sections in the Sections class or specify a new section.
        /// </remarks>
        private static readonly string MethodSection = Sections.TextFunctions;

        /// <summary>The data type of the resulting column from this calculation.
        /// </summary>
        private static readonly DataType ResultingDataType = DataType.String;


        public GenerateLinkMethod() 
            : base(MethodName, Namespace, ResultingDataType, MethodDisplayName, MethodDescription, MethodSection)
        {
        }

        protected override void CalculateRowValueCore(DataValue[] arguments, DataValue<string> result)
        {
            string uid = ((DataValue<string>)arguments[0]).ValidValue;
            string uname = ((DataValue<string>)arguments[1]).ValidValue;
            string orgid = ((DataValue<string>)arguments[2]).ValidValue;
            string orgname = ((DataValue<string>)arguments[3]).ValidValue;
            string pname = ((DataValue<string>)arguments[4]).ValidValue;
            string pcid = ((DataValue<string>)arguments[5]).ValidValue;
            string timestamp = ((DataValue<string>)arguments[6]).ValidValue;
            string appointkey = ((DataValue<string>)arguments[7]).ValidValue;

            string json = $@"""uid"":""{uid}"",""uname"":""{uname}"",""orgid"":""{orgid}"",""orgname"":""{orgname}"",""pname"":""{pname}"",""pcid"":""{pcid}"",""timestamp"":""{timestamp}"",""appointkey"":""{appointkey}""";

            json = "{" + json + "}";

            result.ValidValue = HttpUtility.UrlEncode(ECBAESEncrypt(json, "webdoqleiviewkey"));
        }

        protected override void SpecifyArgumentTypesCore(ArgumentTypeList argumentTypes)
        {
            argumentTypes.Add(DataType.String);
            argumentTypes.Add(DataType.String);
            argumentTypes.Add(DataType.String);
            argumentTypes.Add(DataType.String);
            argumentTypes.Add(DataType.String);
            argumentTypes.Add(DataType.String);
            argumentTypes.Add(DataType.String);
            argumentTypes.Add(DataType.String);
        }

        private static string ECBAESEncrypt(String Data, String Key)
        {
            if (string.IsNullOrEmpty(Key))
            {
                return string.Empty;
            }

            MemoryStream mStream = new MemoryStream();
            RijndaelManaged aes = new RijndaelManaged();

            byte[] plainBytes = Encoding.UTF8.GetBytes(Data);

            byte[] bKey = new Byte[16];
            byte[] keyb = Encoding.UTF8.GetBytes(Key);
            Array.Copy(keyb, bKey, keyb.Length);

            aes.Mode = CipherMode.ECB;
            aes.Padding = PaddingMode.Zeros;
            aes.KeySize = 128;
            //aes.Key = _key;  
            aes.Key = bKey;
            var sec = aes.BlockSize;
            //aes.IV = _iV;  
            CryptoStream cryptoStream = new CryptoStream(mStream, aes.CreateEncryptor(), CryptoStreamMode.Write);
            try
            {
                cryptoStream.Write(plainBytes, 0, plainBytes.Length);
                cryptoStream.FlushFinalBlock();
                return Convert.ToBase64String(mStream.ToArray());
            }
            finally
            {
                cryptoStream.Close();
                mStream.Close();
                aes.Clear();
            }
        }
    }
}
