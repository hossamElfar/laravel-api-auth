<?php

namespace App\Http\Controllers\API;

use Illuminate\Http\Request;

use App\Http\Requests;
use App\Http\Controllers\Controller;
use Illuminate\Support\Facades\Hash;
use Tymon\JWTAuth\Exceptions\JWTException;
use Tymon\JWTAuth\Exceptions\TokenInvalidException;

use Tymon\JWTAuth\Token;
use App\User;
use JWTAuth;
use JWTFactory;
use Response;
use Validator;
use Mail;
use Auth;


class AuthAPIController extends Controller
{
    /**
     * Create a new authentication controller instance.
     *
     * @return void
     */
    public function __construct()
    {
        $this->middleware('auth')->only('update', 'updatePassword');
    }

    /**
     * Get a validator for an incoming registration request.
     *
     * @param  array $data
     * @return \Illuminate\Contracts\Validation\Validator
     */
    protected function validator(array $data)
    {
        return Validator::make($data, [
            'name' => 'required|max:255',
            'email' => 'required|email|max:255|unique:users',
            'password' => 'required|min:6',
            'phone' => 'required',
        ]);
    }

    /**
     * Create a new user instance after a valid registration.
     *
     * @param  array $data
     * @return User
     */
    protected function create(array $data)
    {
        return User::create([
            'name' => $data['name'],
            'email' => $data['email'],
            'password' => bcrypt($data['password']),
            'phone' => $data['phone'],
        ]);
    }

    /**
     * Register new user
     *
     * @param Request $request
     * @return mixed
     */
    public function register(Request $request)
    {
        $validator = $this->validator($request->all());

        if ($validator->fails())
            return response()->json($validator->errors(), 302);
        $this->create($request->all());

        return response()->json(['message' => 'Thank you for registering.'], 200);
    }

    /**
     * Validator to validate the login paramters
     *
     * @param $data
     * @return mixed
     */
    public function validatorLogin($data)
    {
        return Validator::make($data, [
            'email' => 'required',
            'password' => 'required|min:6',
        ]);
    }

    /**
     * Login for a User
     * @param  Request $request : must contain email and password of the User
     * @return json response containing an error in case of invalid credentials or
     * a server error or the token in case of valid credentials
     */
    public function login(Request $request)
    {
        // verify the credentials
        $validator = $this->validatorLogin($request->all());

        if ($validator->fails())
            return response()->json($validator->errors(), 302);

        $credentials = $request->only('email', 'password');
        if (!Auth::attempt($credentials, false, false))
            return response()->json(['error' => 'Invalid Credentials'], 401);

        //create token
        try {
            $user = User::where('email', '=', $credentials['email'])->first();
            $customClaims = ['type' => 'volunteer',
                'id' => $user->id,
                'email' => $user->email];
            $payload = JWTFactory::make($customClaims);
            $token = JWTAuth::encode($payload);
        } catch (JWTException $e) {
            dd($e);
            // something went wrong
            return response()->json(['error' => 'Could not create token'], 500);
        }

        // no errors, return the token
        return response()->json(['token' => $token->get(), 'status' => 'Logged In successfully'], 200);

    }

    /**
     * Update User Profile
     *
     * @param Request $request
     * @return mixed
     */
    public function update(Request $request)
    {
        try{
            $data = $request->all();
            $user = Auth::user();
            $user->update($data);
            $user->save();
            return response()->json(['user'=>$user,'status' => 'Updated In successfully'], 200);
        }catch (\Exception $e){
            return response()->json(['status' => 'Already taken email' ], 500);
        }

    }

    /**
     * Update The authenticated user password
     * 
     * @param Request $request
     * @return mixed
     */
    public function updatePassword(Request $request)
    {
        $user = Auth::user();
        $data = $request->all();
        $validation = Validator::make($data, [
            'password' => 'required',
            'new_password' => 'required|different:password'
        ]);

        if ($validation->fails()) {
            $data1['statues'] = "302 Ok";
            $data1['error'] = "couldn't update password";
            $data1['data'] = $validation->errors();
            return response()->json($data1, 302);
        }

        $user->password = Hash::make($data['new_password']);
        $user->save();
        $data1['statues'] = "200 Ok";
        $data1['error'] = null;
        $data1['data'] = null;
        return response()->json($data1, 200);
    }

    /**
     * Get User Info by ID
     *
     * @param $id
     * @return mixed
     */
    public function show($id)
    {
        $user = User::find($id);
        if ($user != null){
            return response()->json(['user' => $user], 200);
        }else{
            return response()->json(['status' => 'There is no user with id '. $id], 404);
        }
    }


}
