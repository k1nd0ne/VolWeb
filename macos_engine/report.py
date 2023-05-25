import markdown, datetime
from windows_engine.models import *
from investigations.models import ImageSignature


def report(case):
    # FILTERING STEP#
    signatures = ImageSignature.objects.get(investigation=case)

    

    # BEGIN HEADER#
    html = markdown.markdown("# 📄 Investigation report : " + case.title)
    text = "# 📄 Investigation report : " + case.title + "\n"

    html += markdown.markdown(case.description)
    text += case.description

    html += markdown.markdown("## 🧬 Case metadata ")
    text += "## 🧬 Case metadata \n"

    html += markdown.markdown("**Report date** : " + str(datetime.datetime.now()))
    text += "**Report date** : " + str(datetime.datetime.now()) + " \n"

    html += markdown.markdown("**Memory image signatures :**")
    text += "**Memory image signatures :** \n"

    html += markdown.markdown(
        "* MD5 : " + signatures.md5 + "\n * SHA1 : " + signatures.sha1 + "\n * SHA256 : " + signatures.sha256,
        extensions=['sane_lists'])
    text += "* MD5 : " + signatures.md5 + "\n * SHA1 : " + signatures.sha1 + "\n * SHA256 : ""* MD5 : " + signatures.md5 + "\n * SHA1 : " + signatures.sha1 + "\n * SHA256 : "

    html += markdown.markdown("**Investigator(s) on the case :** " + case.investigators)
    text += "**Investigator(s) on the case :** " + case.investigators + " \n"

    html += markdown.markdown("***This report was automatically generated with VolWeb.***")
    text += "***This report was automatically generated with VolWeb.*** \n"
    # END HEADER #

    # BEGIN EVIDENCE ITEMS #

    html += markdown.markdown("## 🟥 Evidence")
    text += "## 🟥 Evidence"

    html += markdown.markdown(
        "The following artifacts were marked as **evidence** and should be considered as proof that is relevant to the investigation.")
    text += "The following artifacts were marked as **evidence** and should be considered as proof that is relevant to the investigation. \n"

   

    # END EVIDENCE ITEMS #

    # BEGIN SUSPICIOUS ITEMS #
    html += markdown.markdown("## 🟨 Suspicious items")
    text += "## 🟨 Suspicious items"

    html += markdown.markdown(
        "The following artifacts were marked as **suspicious** and should be considered by the reader for further investigation.")
    text += "The following artifacts were marked as **suspicious** and should be considered by the reader for further investigation. \n"



    # END SUSPICIOUS ITEMS #

    return html, text
