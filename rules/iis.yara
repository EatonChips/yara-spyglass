rule yara
{
    meta:
        description = "Microsoft IIS"
        confidence = 9

    strings:
        $a = /.*IIS.*/

    condition:
        $a
}


