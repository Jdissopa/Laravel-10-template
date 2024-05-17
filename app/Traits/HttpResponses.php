<?php

namespace App\Traits;

trait HttpResponses
{
    protected function success($data, $message=null, $code = 200)
    {
        return response()->json([
            'status'    => 'Successful',
            'message'   => $message,
            'data'      => $data
        ], $code);
    }

    protected function error($errors, $message=null, $code = 400)
    {
        return response()->json([
            'status'    => 'Error',
            'message'   => $message,
            'errors'    => $errors
        ], $code);
    }
}
