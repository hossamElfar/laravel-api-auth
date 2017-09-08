<?php

/*
|--------------------------------------------------------------------------
| Web Routes
|--------------------------------------------------------------------------
|
| Here is where you can register web routes for your application. These
| routes are loaded by the RouteServiceProvider within a group which
| contains the "web" middleware group. Now create something great!
|
*/

Route::get('/', function () {
    return view('welcome');
});

Auth::routes();

Route::get('/home', 'HomeController@index')->name('home');

Route::group(['prefix' => 'api/v1','middleware' => 'api'], function () {

    /**
     * Users Authentication
     */
    Route::post('register', 'API\AuthAPIController@register');
    Route::post('login', 'API\AuthAPIController@login');
    Route::patch('update','API\AuthAPIController@update');
    Route::post('update_password','API\AuthAPIController@updatePassword');
    Route::get('user/{id}','API\AuthAPIController@show');
    
});
