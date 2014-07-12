using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Xml.Linq;

namespace Meddle
{
  class VarTypes
  {
    private List<VarType> _types;
    private PythonBoss _pyBoss;

    public VarTypes(XDocument reader, PythonBoss pyBoss)
    {
      _pyBoss = pyBoss;

      // Load all the <type>'s but in reverse-order because of
      // dependencies on one-another.
      IEnumerable<XElement> elements = reader.Descendants("types").Elements("type");

      _types = new List<VarType>(10);
      for (int i = elements.Count() - 1; i >= 0; i--)
      {
        // Load this <type> description
        _types.Add(new VarType(pyBoss, this, elements.ElementAt(i)));
      }
    }
  }
}
