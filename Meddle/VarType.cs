using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Xml.Linq;

namespace Meddle
{
  class VarType
  {
    private string _pyLocal = "";
    private string _name = "";
    private VarTypes _parent;
    private PythonBoss _pyBoss;

    public VarType(PythonBoss pyBoss, VarTypes varTypes, XElement element)
    {
      // Load this variable type

      _pyBoss = pyBoss;

      // Load the scripts
      foreach (XElement el in element.Elements("global_script"))
        if (!_pyBoss.AddCode(el.Value, "variable types <global_script>"))
          return;
      foreach (XElement el in element.Elements("local_script"))
        _pyLocal += "\r\n" + element.Value;

      // Load the name
      XElement name = element.Element("name");
      if (name != null) _name = name.Value;

      _parent = varTypes;
    }
  }
}
