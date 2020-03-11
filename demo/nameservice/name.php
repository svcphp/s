<?php

function getName($data)
{
	try {
		return s::ok(['name' => file_get_contents(sys_get_temp_dir() . '/name.txt')]);
	} catch (Exception $ex) {
		return s::failed(-1, $ex);
	}
}

function setName($data)
{
	try {
		if (file_put_contents(sys_get_temp_dir() . '/name.txt', $data['name'])) {
			return s::ok(null);
		} else {
			return s::failed(-1, 'failed to save name file');
		}
	} catch (Exception $ex) {
		return s::failed(-2, $ex);
	}
}
