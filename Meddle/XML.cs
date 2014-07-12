using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.IO;
using System.Xml;

namespace Meddle
{
    static class XML
    {
        public static string Consolidate(string config_file)
        {
            // Grab the consolidated xml contents by grabbing all the imports
            List<string> includes = new List<string>(5);

            // Now append the wrapper xml tag
            return AddWrapper(ConsolidateImports(config_file, ref includes));
        }

        public static string AddWrapper(string xml)
        {
            return "<?xml version=\"1.0\" encoding=\"utf-8\" ?>\r\n<wrapper>\r\n" + xml.Replace("<?xml version=\"1.0\" encoding=\"utf-8\" ?>", "") + "\r\n</wrapper>";
        }

        private static string ConsolidateImports(string xml_file, ref List<string> loaded_files)
        {
            if (File.Exists(xml_file))
            {
                Console.WriteLine("Including config description '" + xml_file + "'.");

                // Read in this file
                string contents = File.ReadAllText(xml_file);

                try
                {
                    // Include the <import> specified includes.
                    using (XmlReader reader = XmlReader.Create(new StringReader(AddWrapper(contents))))
                    {
                        while (reader.ReadToFollowing("include"))
                        {
                            string include = reader.ReadElementContentAsString().ToLower();
                            if (!loaded_files.Contains(include))
                            {
                                // Include this import
                                loaded_files.Add(include);
                                contents = contents + "\n\n" + ConsolidateImports(include, ref loaded_files);
                            }
                        }
                    }
                }
                catch (Exception ex)
                {
                    Console.WriteLine("Error when processing xml config file '" + xml_file + "':");
                    Console.WriteLine(ex.ToString());
                }

                return contents;
            }
            Console.WriteLine("Error: Unable to locate imported XML file '" + xml_file + "'.");
            return "";
        }
    }
}
