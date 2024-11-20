<?php

namespace App\Http\Controllers;

use Illuminate\Http\Request;

class XmlController extends Controller
{
    public function firmarXml(Request $request)
    {   
        return response()->json(true);
    }
}