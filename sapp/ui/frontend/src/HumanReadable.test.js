/**
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

import {makeDalvikClassHumanReadable} from './HumanReadable'


describe('makeDalvikClassHumanReadable', ()=>{
    test('returns human readable return_type', ()=>{
        expect(makeDalvikClassHumanReadable("V")).toBe("void");
        expect(makeDalvikClassHumanReadable("I")).toBe("int");
        expect(makeDalvikClassHumanReadable("Z")).toBe("boolean");
    })

    test('returns human readable class name', ()=>{
        expect(makeDalvikClassHumanReadable("Lcom/example/myapplication/MainActivity")).toBe("MainActivity");
        expect(makeDalvikClassHumanReadable("Landroid/os/Bundle;")).toBe("Bundle");
    })

})
