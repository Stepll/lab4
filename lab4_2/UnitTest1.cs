using IIG.CoSFE.DatabaseUtils;
using IIG.FileWorker;
using IIG.PasswordHashingUtils;
using System;
using System.IO;
using System.Linq;
using Xunit;
[assembly: CollectionBehavior(DisableTestParallelization = true)]

namespace lab4_2
{
    public class PasswordHasher_Integration
    {

        AuthDatabaseUtils adu = new AuthDatabaseUtils(@"DESKTOP-OHNLA7H", @"IIG.CoSWE.AuthDB", true, @"coswe", @"L}EjpfCgru9X@GLj", 15);

        [Theory]
        [InlineData("qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq", "rui")]
        [InlineData("rui", "qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq")]
        public void AuthDbCheckTrue(string pass, string login)
        {
            string hashed = PasswordHasher.GetHash(pass, login);
            adu.AddCredentials(login, hashed);
            Assert.True(adu.CheckCredentials(login, hashed));
        }

        [Theory]
        [InlineData("qweqweqwe", "some")]
        [InlineData("", "notValid")]
        public void AuthDbAddFalse(string pass, string login)
        {

            adu.AddCredentials(login, pass);
            Assert.False(adu.CheckCredentials(login, pass));
        }



        [Theory]
        [InlineData("valid data", "qweqwewqeqweqweqwe")]
        [InlineData("qqqqqqqqqqqq", "ssssssssssss")]
        public void AuthDbAddTrue(string pass, string login)
        {
            string hashed = PasswordHasher.GetHash(pass, login);
            adu.AddCredentials(login, hashed);
            Assert.True(adu.CheckCredentials(login, hashed));
        }

        [Fact]
        public void DeleteEntry()
        {
            string login = "naruto";
            string pass = "sakura";
            string hashed = PasswordHasher.GetHash(pass, login);
            adu.AddCredentials(login, hashed);
            Assert.True(adu.CheckCredentials(login, hashed), "Add check");
            adu.DeleteCredentials(login, hashed);
            Assert.False(adu.CheckCredentials(login, hashed), "Delete check");
        }

        [Fact]
        public void DeleteEntryNonExistant()
        {
            Assert.False(adu.DeleteCredentials("non_existant", "aswell"), "Will fail but logically should be false");
        }


        [Fact]
        public void updateNonExistant()
        {

            string login_updated = "updated";
            string pass_updated = "some_pass";
            string start_login = "some_login";
            string start_hashed = PasswordHasher.GetHash("start_pass", start_login);
            string hashed_upd = PasswordHasher.GetHash(pass_updated, login_updated);
            Assert.False(adu.UpdateCredentials(start_login, start_hashed, login_updated, hashed_upd));
            Assert.False(adu.CheckCredentials(login_updated, hashed_upd));
        }

    }
    public class Fileworker_Integration
    {
        StorageDatabaseUtils sdu = new StorageDatabaseUtils(@"DESKTOP-OHNLA7H", @"IIG.CoSWE.AuthDB", true, @"coswe", @"L}EjpfCgru9X@GLj", 15);


        [Fact]
        public void DeleteFileCheckFail()
        {
            Assert.False(sdu.DeleteFile(-1), "will be failed, but logically should be false");
        }

        [Fact]
        public void GetFilesEmptyCheck()
        {
            Assert.True(sdu.GetFiles("no_such_filename.dot").Rows.Count == 0);
        }

        [Fact]
        public void GetFileErrorCheck()
        {
            byte[] emptyByte;
            string emptyFilename;
            Assert.False(sdu.GetFile(-1, out emptyFilename, out emptyByte));
        }
    }


}
