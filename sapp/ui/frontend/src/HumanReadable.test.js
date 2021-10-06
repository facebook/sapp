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
