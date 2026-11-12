using System;
using System.Collections.Generic;
using System.Data.SqlClient;
using System.Linq;
using System.Threading.Tasks;
using System.Web.Mvc;

namespace Cs.Fixes
{
    // An interface nothing in the solution implements.
    public interface IBareSvc
    {
        string Canonicalize(string s);
    }

    // Engine gaps: constructs the IR lowers to `unknown`, body-less targets, lambdas, tuple loops.
    public class Gaps : Controller
    {
        private IBareSvc _svc;
        private SqlConnection _c;
        private Func<string, string>[] _delegates;

        private void Sql(string s) { var cmd = new SqlCommand(s, _c); }

        private string SqlS(string s) { var cmd = new SqlCommand(s, _c); return s; }

        public void SwitchExpr(int k)
        {
            var q = k switch { 1 => Request["a"], _ => "x" };
            var cmd = new SqlCommand(q, _c);
        }

        public void SwitchConst(int k)
        {
            var q = k switch { 1 => "a", _ => "x" };
            var cmd = new SqlCommand(q, _c);
        }

        public void BodylessTarget()
        {
            var n = _svc.Canonicalize(Request["q"]);
            var cmd = new SqlCommand(n, _c);
        }

        public void TaskRun()
        {
            var q = Request["q"];
            Task.Run(() => Sql(q));
        }

        public void TaskRunConst()
        {
            var q = Request["q"];
            Task.Run(() => Sql("const"));
        }

        public void LambdaDoesNotLeak()
        {
            var q = "clean";
            Task.Run(() => { q = Request["q"]; });
            var cmd = new SqlCommand(q, _c);
        }

        public void ForEachWritesBack()
        {
            var list = new List<string> { Request["a"] };
            var q = "clean";
            list.ForEach(x => q += x);
            Sql(q);
        }

        public void ForEachWritesBackClean()
        {
            var list = new List<string> { "a" };
            var q = "clean";
            list.ForEach(x => q += x);
            Sql(q);
        }

        public void StaticWhere()
        {
            var list = new List<string> { Request["a"] };
            Enumerable.Where(list, x => { Sql(x); return true; });
        }

        public void StaticWhereClean()
        {
            var list = new List<string> { "a" };
            Enumerable.Where(list, x => { Sql(x); return true; });
        }

        public void StaticSelect()
        {
            var list = new List<string> { Request["a"] };
            var r = Enumerable.Select(list, x => SqlS(x)).ToList();
        }

        public void TupleAssign()
        {
            string a, b;
            (a, b) = (Request["a"], "x");
            Sql(a);
        }

        public void TupleAssignClean()
        {
            string a, b;
            (a, b) = ("y", "x");
            Sql(a);
        }

        public void ForEachLambda()
        {
            var list = new List<string> { Request["a"] };
            list.ForEach(x => Sql(x));
        }

        public void ForEachLambdaClean()
        {
            var list = new List<string> { "a", "b" };
            list.ForEach(x => Sql(x));
        }

        public void SelectClosure()
        {
            var q = Request["q"];
            var list = new List<string> { "a" };
            var rs = list.Select(x => SqlS(x + q)).ToList();
        }

        public void SelectParamClean()
        {
            var list = new List<string> { "a" };
            var rs = list.Select(x => SqlS(x)).ToList();
        }

        public void TupleLoop()
        {
            var pairs = new Dictionary<string, string>();
            pairs.Add("k", Request["a"]);
            foreach (var (k, v) in pairs)
            {
                var cmd = new SqlCommand(v, _c);
            }
        }

        public void IndexedCallee()
        {
            var q = _delegates[0](Request["q"]);
            var cmd = new SqlCommand(q, _c);
        }
    }
}
